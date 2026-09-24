const path = require('path');
require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const app = express();
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || (isProduction ? '' : 'local-development-only-change-me');
const ADMIN_ID = process.env.ADMIN_ID || (isProduction ? '' : 'admin');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || (isProduction ? '' : 'admin123');
if (!JWT_SECRET || JWT_SECRET.length < 32 || !ADMIN_ID || !ADMIN_PASSWORD) {
  throw new Error('JWT_SECRET, ADMIN_ID, and ADMIN_PASSWORD must be set. JWT_SECRET must be at least 32 characters.');
}
const uploadsDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

app.use(express.json({ limit: '2mb' }));
// Permit the UI to be opened directly from disk during local development.
// When it is served by this Express app, these headers are harmless.
app.use((req, res, next) => {
  const allowedOrigin = process.env.ALLOWED_ORIGIN || (isProduction ? '' : '*');
  if (allowedOrigin) res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'");
  if (isProduction) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
const rateBuckets = new Map();
function rateLimit({ windowMs, max }) {
  return (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const bucket = rateBuckets.get(key);
    if (!bucket || now - bucket.startedAt >= windowMs) rateBuckets.set(key, { startedAt: now, count: 1 });
    else if (++bucket.count > max) return res.status(429).json({ message: 'Too many requests. Try again later.' });
    next();
  };
}
const authRateLimit = rateLimit({ windowMs: 10 * 60 * 1000, max: 20 });
app.use(express.static(path.join(__dirname), { dotfiles: 'deny' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

const employeeSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  employeeId: { type: String, required: true, unique: true, trim: true, uppercase: true },
  mobile: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  passwordResetVersion: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  alternateMobile: { type: String, default: '' },
  address: { type: String, default: '' },
  aadhaarFile: { type: String, default: '' },
  aadhaarBackFile: { type: String, default: '' },
  profilePhoto: { type: String, default: '' },
  canViewCustomerFiles: { type: Boolean, default: false }
}, { timestamps: true });

const pendingRegistrationSchema = new mongoose.Schema({
  name: { type: String, required: true },
  employeeId: { type: String, required: true, uppercase: true },
  mobile: { type: String, required: true },
  email: { type: String, required: true, lowercase: true, unique: true },
  passwordHash: { type: String, required: true },
  otpHash: { type: String, required: true },
  otpExpiresAt: { type: Date, required: true },
  attempts: { type: Number, default: 0 }
}, { timestamps: true });
pendingRegistrationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 86400 });

const passwordResetSchema = new mongoose.Schema({
  employee: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true, unique: true },
  otpHash: { type: String, required: true },
  otpExpiresAt: { type: Date, required: true },
  attempts: { type: Number, default: 0 }
}, { timestamps: true });
passwordResetSchema.index({ createdAt: 1 }, { expireAfterSeconds: 86400 });

const customerSchema = new mongoose.Schema({
  employee: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true },
  fileNumber: { type: String, required: true, trim: true },
  status: { type: String, enum: ['pending', 'confirmed'], default: 'pending' },
  data: { type: mongoose.Schema.Types.Mixed, required: true }
}, { timestamps: true });
customerSchema.index({ employee: 1, fileNumber: 1 }, { unique: true });

const Employee = mongoose.model('Employee', employeeSchema);
const PendingRegistration = mongoose.model('PendingRegistration', pendingRegistrationSchema);
const PasswordReset = mongoose.model('PasswordReset', passwordResetSchema);
const Customer = mongoose.model('Customer', customerSchema);

function publicEmployee(employee) {
  return {
    id: employee._id, name: employee.name, employeeId: employee.employeeId,
    mobile: employee.mobile, email: employee.email, status: employee.status,
    alternateMobile: employee.alternateMobile, address: employee.address,
    aadhaarFile: employee.aadhaarFile, aadhaarBackFile: employee.aadhaarBackFile, profilePhoto: employee.profilePhoto,
    canViewCustomerFiles: employee.canViewCustomerFiles, createdAt: employee.createdAt
  };
}
function signToken(employee) {
  return jwt.sign({ sub: employee._id.toString(), role: 'employee' }, JWT_SECRET, { expiresIn: '8h', issuer: 'deeya-invest', audience: 'deeya-invest-ui' });
}
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || (req.path.startsWith('/api/files/') ? req.query.token : '');
  if (!token) return res.status(401).json({ message: 'Authentication required.' });
  try {
    req.auth = jwt.verify(token, JWT_SECRET, { issuer: 'deeya-invest', audience: 'deeya-invest-ui' });
    if (!['admin', 'employee'].includes(req.auth.role)) throw new Error('Invalid role');
    if (req.auth.role === 'employee' && !mongoose.isValidObjectId(req.auth.sub)) throw new Error('Invalid subject');
    next();
  }
  catch { return res.status(401).json({ message: 'Your session has expired. Please log in again.' }); }
}
async function requireEmployee(req, res, next) {
  if (req.auth?.role !== 'employee') return res.status(403).json({ message: 'Employee access required.' });
  try {
    const employee = await Employee.findById(req.auth.sub).select('status');
    if (!employee || employee.status !== 'approved') return res.status(403).json({ message: 'Employee access is not approved.' });
    next();
  } catch (error) { next(error); }
}
function requireAdmin(req, res, next) {
  if (req.auth?.role !== 'admin') return res.status(403).json({ message: 'Admin access required.' });
  next();
}
app.get('/api/files/:filename', requireAuth, async (req, res, next) => {
  try {
    const filename = path.basename(req.params.filename);
    if (filename !== req.params.filename) return res.status(400).json({ message: 'Invalid file name.' });

    // Admin users must be able to open any uploaded photo or document.
    if (req.auth.role === 'admin') {
      return res.sendFile(path.join(uploadsDir, filename));
    }

    const employee = await Employee.findById(req.auth.sub).select('profilePhoto aadhaarFile aadhaarBackFile canViewCustomerFiles');
    const ownCustomers = await Customer.find({ employee: req.auth.sub }).select('data');
    const ownsFile = [employee?.profilePhoto, employee?.aadhaarFile, employee?.aadhaarBackFile, ...ownCustomers.map(customer => customer.data)]
      .some(value => containsFileReference(value, filename));

    if (!employee?.canViewCustomerFiles && !ownsFile) {
      return res.status(403).json({ message: 'Customer file access has not been granted.' });
    }

    res.sendFile(path.join(uploadsDir, filename));
  } catch (error) { next(error); }
});
function containsFileReference(value, filename) {
  if (typeof value === 'string') return value === `/uploads/${filename}`;
  if (!value || typeof value !== 'object') return false;
  return Object.values(value).some(item => containsFileReference(item, filename));
}
function validMobile(value) { return /^\d{10}$/.test(String(value || '')); }
function createOtp() { return crypto.randomInt(100000, 1000000).toString(); }
function logOtpForAdmin(mobile, otp) {
  console.log(`[ADMIN ONLY] OTP for mobile ${mobile}: ${otp} (expires in 10 minutes)`);
}

app.post('/api/auth/register', authRateLimit, async (req, res, next) => {
  try {
    const { name, employeeId, mobile, email, password } = req.body;
    const normalizedId = String(employeeId || '').trim().toUpperCase();
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!name?.trim() || !normalizedId || !validMobile(mobile) || !normalizedEmail || String(password || '').length < 12) {
      return res.status(400).json({ message: 'Enter a name, employee ID, 10-digit mobile number, email, and a password of at least 12 characters.' });
    }
    if (await Employee.exists({ $or: [{ employeeId: normalizedId }, { email: normalizedEmail }] })) {
      return res.status(409).json({ message: 'An employee with this ID or email already exists.' });
    }
    const otp = createOtp();
    const passwordHash = await bcrypt.hash(password, 12);
    const otpHash = await bcrypt.hash(otp, 10);
    await PendingRegistration.findOneAndUpdate(
      { email: normalizedEmail },
      { name: name.trim(), employeeId: normalizedId, mobile, email: normalizedEmail, passwordHash, otpHash, otpExpiresAt: new Date(Date.now() + 10 * 60 * 1000), attempts: 0 },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    logOtpForAdmin(mobile, otp);
    res.status(201).json({ message: 'OTP printed in the admin terminal. Ask the admin for the OTP.', expiresInSeconds: 600 });
  } catch (error) { next(error); }
});

app.post('/api/auth/resend-otp', authRateLimit, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const pending = await PendingRegistration.findOne({ email });
    if (!pending) return res.status(404).json({ message: 'No pending registration found. Register again.' });
    const otp = createOtp();
    pending.otpHash = await bcrypt.hash(otp, 10);
    pending.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
    pending.attempts = 0;
    await pending.save();
    logOtpForAdmin(pending.mobile, otp);
    res.json({ message: 'New OTP printed in the admin terminal. Ask the admin for it.', expiresInSeconds: 600 });
  } catch (error) { next(error); }
});

app.post('/api/auth/verify-otp', authRateLimit, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const otp = String(req.body.otp || '').trim();
    const pending = await PendingRegistration.findOne({ email });
    if (!pending) return res.status(404).json({ message: 'No pending registration found.' });
    if (pending.otpExpiresAt < new Date()) return res.status(400).json({ message: 'OTP has expired. Request a new code.' });
    if (pending.attempts >= 5) return res.status(429).json({ message: 'Too many attempts. Request a new code.' });
    if (!(await bcrypt.compare(otp, pending.otpHash))) {
      pending.attempts += 1; await pending.save();
      return res.status(400).json({ message: 'Incorrect OTP.' });
    }
    const employee = await Employee.create({ name: pending.name, employeeId: pending.employeeId, mobile: pending.mobile, email: pending.email, passwordHash: pending.passwordHash });
    await PendingRegistration.deleteOne({ _id: pending._id });
    res.status(201).json({ message: 'Email verified. Your account is awaiting admin approval.', employee: publicEmployee(employee) });
  } catch (error) {
    if (error?.code === 11000) return res.status(409).json({ message: 'This employee ID or email is already registered.' });
    next(error);
  }
});

app.post('/api/auth/request-password-reset', authRateLimit, async (req, res, next) => {
  try {
    const employee = await Employee.findOne({ employeeId: String(req.body.employeeId || '').trim().toUpperCase() });
    if (!employee) return res.status(404).json({ message: 'Employee ID not found.' });
    const otp = createOtp();
    await PasswordReset.findOneAndUpdate(
      { employee: employee._id },
      { otpHash: await bcrypt.hash(otp, 10), otpExpiresAt: new Date(Date.now() + 10 * 60 * 1000), attempts: 0 },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    logOtpForAdmin(employee.mobile, otp);
    res.json({ message: 'A password-reset OTP was generated. Ask the admin for it.' });
  } catch (error) { next(error); }
});

app.post('/api/auth/verify-password-reset-otp', authRateLimit, async (req, res, next) => {
  try {
    const employee = await Employee.findOne({ employeeId: String(req.body.employeeId || '').trim().toUpperCase() });
    const reset = employee && await PasswordReset.findOne({ employee: employee._id });
    if (!reset) return res.status(400).json({ message: 'Request a password-reset OTP first.' });
    if (reset.otpExpiresAt < new Date()) return res.status(400).json({ message: 'OTP has expired. Request a new code.' });
    if (reset.attempts >= 5) return res.status(429).json({ message: 'Too many attempts. Request a new OTP.' });
    if (!(await bcrypt.compare(String(req.body.otp || '').trim(), reset.otpHash))) {
      reset.attempts += 1; await reset.save();
      return res.status(400).json({ message: 'Incorrect OTP.' });
    }
    await PasswordReset.deleteOne({ _id: reset._id });
    const resetToken = jwt.sign({ sub: employee._id.toString(), purpose: 'password-reset', version: employee.passwordResetVersion || 0 }, JWT_SECRET, { expiresIn: '10m', issuer: 'deeya-invest', audience: 'deeya-invest-reset' });
    res.json({ message: 'OTP verified. You can now choose a new password.', resetToken });
  } catch (error) { next(error); }
});

app.post('/api/auth/reset-password', authRateLimit, async (req, res, next) => {
  try {
    const { resetToken, password } = req.body;
    if (String(password || '').length < 12) return res.status(400).json({ message: 'New password must be at least 12 characters.' });
    let grant;
    try { grant = jwt.verify(resetToken, JWT_SECRET, { issuer: 'deeya-invest', audience: 'deeya-invest-reset' }); }
    catch { return res.status(401).json({ message: 'Password-reset session has expired. Request a new OTP.' }); }
    if (grant.purpose !== 'password-reset') return res.status(401).json({ message: 'Invalid password-reset session.' });
    const employee = await Employee.findById(grant.sub);
    if (!employee || (employee.passwordResetVersion || 0) !== grant.version) return res.status(401).json({ message: 'Password-reset session is no longer valid. Request a new OTP.' });
    employee.passwordHash = await bcrypt.hash(password, 12);
    employee.passwordResetVersion = (employee.passwordResetVersion || 0) + 1;
    await employee.save();
    res.json({ message: 'Password reset successfully. You can now log in.' });
  } catch (error) { next(error); }
});

app.post('/api/auth/employee-login', authRateLimit, async (req, res, next) => {
  try {
    const employee = await Employee.findOne({ employeeId: String(req.body.employeeId || '').trim().toUpperCase() });
    if (!employee || !(await bcrypt.compare(String(req.body.password || ''), employee.passwordHash))) return res.status(401).json({ message: 'Invalid employee ID or password.' });
    if (employee.status !== 'approved') return res.status(403).json({ message: employee.status === 'pending' ? 'Admin approval is pending.' : 'This employee account has been rejected.' });
    res.json({ token: signToken(employee), employee: publicEmployee(employee) });
  } catch (error) { next(error); }
});

app.post('/api/auth/admin-login', authRateLimit, async (req, res) => {
  if (req.body.adminId !== ADMIN_ID || !(await bcrypt.compare(String(req.body.password || ''), ADMIN_PASSWORD))) return res.status(401).json({ message: 'Invalid admin ID or password.' });
  res.json({ token: jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '8h', issuer: 'deeya-invest', audience: 'deeya-invest-ui' }) });
});
app.get('/api/admin/employees', requireAuth, requireAdmin, async (req, res, next) => {
  try { res.json((await Employee.find().sort({ createdAt: -1 })).map(publicEmployee)); } catch (error) { next(error); }
});
app.get('/api/admin/customers', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const customers = await Customer.find().populate('employee', 'name employeeId email').sort({ createdAt: -1 });
    res.json(customers.map(customer => ({
      customerId: customer._id,
      ...customer.data,
      status: customer.status || 'pending',
      createdAt: customer.createdAt,
      uploadedBy: customer.employee ? {
        name: customer.employee.name,
        employeeId: customer.employee.employeeId,
        email: customer.employee.email
      } : null
    })));
  } catch (error) { next(error); }
});
app.patch('/api/admin/customers/:id/status', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const status = req.body.status;
    if (!['pending', 'confirmed'].includes(status)) return res.status(400).json({ message: 'Invalid customer file status.' });
    const customer = await Customer.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!customer) return res.status(404).json({ message: 'Customer file not found.' });
    res.json({ id: customer._id, status: customer.status, createdAt: customer.createdAt });
  } catch (error) { next(error); }
});
app.delete('/api/admin/customers/:id', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const customer = await Customer.findById(req.params.id);
    if (!customer) return res.status(404).json({ message: 'Customer file not found.' });
    const storedFiles = JSON.stringify(customer.data).match(/\/uploads\/[^"\\]+/g) || [];
    await Promise.all([...new Set(storedFiles)].map(file => fs.promises.unlink(path.join(uploadsDir, path.basename(file))).catch(error => {
      if (error.code !== 'ENOENT') throw error;
    })));
    await customer.deleteOne();
    res.json({ message: 'Customer file deleted successfully.', id: customer._id });
  } catch (error) { next(error); }
});
app.patch('/api/admin/employees/:id/status', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const status = req.body.status;
    if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ message: 'Invalid employee status.' });
    const employee = await Employee.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!employee) return res.status(404).json({ message: 'Employee not found.' });
    res.json({ employee: publicEmployee(employee) });
  } catch (error) { next(error); }
});
app.patch('/api/admin/employees/:id/customer-access', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const employee = await Employee.findByIdAndUpdate(req.params.id, { canViewCustomerFiles: Boolean(req.body.canViewCustomerFiles) }, { new: true });
    if (!employee) return res.status(404).json({ message: 'Employee not found.' });
    res.json({ employee: publicEmployee(employee) });
  } catch (error) { next(error); }
});

app.get('/api/employees/me', requireAuth, requireEmployee, async (req, res, next) => {
  try {
    const employee = await Employee.findById(req.auth.sub);
    if (!employee) return res.status(404).json({ message: 'Employee not found.' });
    res.json({ employee: publicEmployee(employee) });
  } catch (error) { next(error); }
});
const storage = multer.diskStorage({ destination: uploadsDir, filename: (req, file, cb) => cb(null, `${Date.now()}-${crypto.randomUUID()}${path.extname(file.originalname)}`) });
const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.mp4', '.mov', '.avi']);
const allowedUploadType = file => allowedExtensions.has(path.extname(file.originalname).toLowerCase()) && (file.mimetype.startsWith('image/') || [
  'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'video/mp4', 'video/quicktime', 'video/x-msvideo'
].includes(file.mimetype));
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024, files: 30, fields: 50, fieldSize: 100000 }, fileFilter: (req, file, cb) => allowedUploadType(file) ? cb(null, true) : cb(new Error('Allowed files: photos, PDF, Word, Excel, and common video formats.')) });
app.patch('/api/employees/me', requireAuth, requireEmployee, upload.fields([{ name: 'aadhaar', maxCount: 1 }, { name: 'aadhaarBack', maxCount: 1 }, { name: 'profilePhoto', maxCount: 1 }]), async (req, res, next) => {
  try {
    const { alternateMobile = '', address = '' } = req.body;
    if (alternateMobile && !validMobile(alternateMobile)) return res.status(400).json({ message: 'Alternate phone number must be exactly 10 digits.' });
    const employeeRecord = await Employee.findById(req.auth.sub).select('aadhaarFile aadhaarBackFile');
    const aadhaarFile = req.files?.aadhaar?.[0];
    const aadhaarBackFile = req.files?.aadhaarBack?.[0];
    if (!(aadhaarFile || employeeRecord?.aadhaarFile) || !(aadhaarBackFile || employeeRecord?.aadhaarBackFile)) {
      return res.status(400).json({ message: 'Aadhaar front and back photos are required.' });
    }
    const update = { alternateMobile, address: String(address).trim() };
    if (aadhaarFile) update.aadhaarFile = `/uploads/${aadhaarFile.filename}`;
    if (aadhaarBackFile) update.aadhaarBackFile = `/uploads/${aadhaarBackFile.filename}`;
    if (req.files?.profilePhoto?.[0]) update.profilePhoto = `/uploads/${req.files.profilePhoto[0].filename}`;
    const employee = await Employee.findByIdAndUpdate(req.auth.sub, update, { new: true });
    res.json({ employee: publicEmployee(employee) });
  } catch (error) { next(error); }
});

const customerUploadFields = [
  'cusAadhaarFront', 'cusAadhaarBack', 'cusPan', 'cusDlFront', 'cusDlBack', 'cusBill', 'cusFleet', 'cusRcFront', 'cusRcBack', 'cusPhoto',
  'coAadhaarFront', 'coAadhaarBack', 'coPan', 'coBill', 'coRcFront', 'coRcBack', 'coPhoto',
  'gAadhaarFront', 'gAadhaarBack', 'gPan', 'gRcFront', 'gRcBack', 'gFleet', 'gPhoto'
].map(name => ({ name, maxCount: 1 }));

function applyCustomerUploads(data, files, previous = {}) {
  const fileUrl = (name, fallback = '') => files?.[name]?.[0] ? `/uploads/${files[name][0].filename}` : fallback;
  data.documents = data.documents || {};
  data.documents.aadhaar = data.documents.aadhaar || {};
  data.documents.aadhaar.front = fileUrl('cusAadhaarFront', previous.documents?.aadhaar?.front);
  data.documents.aadhaar.back = fileUrl('cusAadhaarBack', previous.documents?.aadhaar?.back);
  data.documents.pan = fileUrl('cusPan', previous.documents?.pan);
  data.documents.dl = data.documents.dl || {};
  data.documents.dl.front = fileUrl('cusDlFront', previous.documents?.dl?.front);
  data.documents.dl.back = fileUrl('cusDlBack', previous.documents?.dl?.back);
  data.documents.electricityBill = fileUrl('cusBill', previous.documents?.electricityBill);
  data.documents.fleet = fileUrl('cusFleet', previous.documents?.fleet);
  data.documents.rc = data.documents.rc || {};
  data.documents.rc.front = fileUrl('cusRcFront', previous.documents?.rc?.front);
  data.documents.rc.back = fileUrl('cusRcBack', previous.documents?.rc?.back);
  data.documents.rc.photo = fileUrl('cusPhoto', previous.documents?.rc?.photo);
  data.documents.photo = data.documents.rc.photo;
  data.coApplicant = data.coApplicant || {};
  data.coApplicant.aadhaar = data.coApplicant.aadhaar || {};
  data.coApplicant.aadhaar.front = fileUrl('coAadhaarFront', previous.coApplicant?.aadhaar?.front);
  data.coApplicant.aadhaar.back = fileUrl('coAadhaarBack', previous.coApplicant?.aadhaar?.back);
  data.coApplicant.pan = fileUrl('coPan', previous.coApplicant?.pan);
  data.coApplicant.electricityBill = fileUrl('coBill', previous.coApplicant?.electricityBill);
  data.coApplicant.rc = data.coApplicant.rc || {};
  data.coApplicant.rc.front = fileUrl('coRcFront', previous.coApplicant?.rc?.front);
  data.coApplicant.rc.back = fileUrl('coRcBack', previous.coApplicant?.rc?.back);
  data.coApplicant.rc.photo = fileUrl('coPhoto', previous.coApplicant?.rc?.photo);
  data.guarantor = data.guarantor || {};
  data.guarantor.aadhaar = data.guarantor.aadhaar || {};
  data.guarantor.aadhaar.front = fileUrl('gAadhaarFront', previous.guarantor?.aadhaar?.front);
  data.guarantor.aadhaar.back = fileUrl('gAadhaarBack', previous.guarantor?.aadhaar?.back);
  data.guarantor.pan = fileUrl('gPan', previous.guarantor?.pan);
  data.guarantor.rc = data.guarantor.rc || {};
  data.guarantor.rc.front = fileUrl('gRcFront', previous.guarantor?.rc?.front);
  data.guarantor.rc.back = fileUrl('gRcBack', previous.guarantor?.rc?.back);
  data.guarantor.rc.photo = fileUrl('gPhoto', previous.guarantor?.rc?.photo);
  data.guarantor.fleet = fileUrl('gFleet', previous.guarantor?.fleet);
  return data;
}

app.post('/api/customers', requireAuth, requireEmployee, upload.fields(customerUploadFields), async (req, res, next) => {
  try {
    const data = JSON.parse(req.body.customerData || '{}');
    if (!data?.id || !data?.name || !validMobile(data.mobile)) return res.status(400).json({ message: 'Customer file number, name, and 10-digit mobile number are required.' });
    applyCustomerUploads(data, req.files);
    const customer = await Customer.create({ employee: req.auth.sub, fileNumber: data.id, data });
    res.status(201).json({ customer: { id: customer._id, ...data, status: customer.status, createdAt: customer.createdAt } });
  } catch (error) { if (error?.code === 11000) return res.status(409).json({ message: 'This customer file number already exists.' }); next(error); }
});
app.patch('/api/customers/:id', requireAuth, requireEmployee, upload.fields(customerUploadFields), async (req, res, next) => {
  try {
    const customer = await Customer.findOne({ _id: req.params.id, employee: req.auth.sub });
    if (!customer) return res.status(404).json({ message: 'Customer file not found.' });
    const data = JSON.parse(req.body.customerData || '{}');
    if (!data?.id || !data?.name || !validMobile(data.mobile)) return res.status(400).json({ message: 'Customer file number, name, and 10-digit mobile number are required.' });
    applyCustomerUploads(data, req.files, customer.data);
    customer.fileNumber = data.id;
    customer.data = data;
    customer.status = 'pending';
    await customer.save();
    res.json({ customer: { id: customer._id, ...data, status: customer.status, createdAt: customer.createdAt } });
  } catch (error) { if (error?.code === 11000) return res.status(409).json({ message: 'This customer file number already exists.' }); next(error); }
});
app.get('/api/customers', requireAuth, requireEmployee, async (req, res, next) => {
  try {
    const employee = await Employee.findById(req.auth.sub).select('canViewCustomerFiles');
    const query = employee?.canViewCustomerFiles ? {} : { employee: req.auth.sub };
    const customers = await Customer.find(query).populate('employee', 'name employeeId email').sort({ createdAt: -1 });
    res.json(customers.map(c => ({
      id: c._id, ...c.data, status: c.status || 'pending', createdAt: c.createdAt,
      uploadedBy: c.employee ? { name: c.employee.name, employeeId: c.employee.employeeId, email: c.employee.email } : null
    })));
  } catch (error) { next(error); }
});
app.get('/api/customers/stats', requireAuth, requireEmployee, async (req, res, next) => {
  try {
    const query = { employee: req.auth.sub };
    const [total, pending] = await Promise.all([
      Customer.countDocuments(query),
      Customer.countDocuments({ ...query, status: { $ne: 'confirmed' } })
    ]);
    res.json({ customers: total, files: total, pending });
  } catch (error) { next(error); }
});

app.use((error, req, res, next) => { console.error(error); res.status(error.status || 500).json({ message: error.message || 'Something went wrong.' }); });

const mongodbUri = process.env.MONGODB_URI?.trim();
if (!mongodbUri) throw new Error('MONGODB_URI must be set in the environment.');
if (!/^mongodb(?:\+srv)?:\/\//.test(mongodbUri)) {
  throw new Error('MONGODB_URI must start with mongodb:// or mongodb+srv://. Copy the complete URI from MongoDB Atlas or use mongodb://127.0.0.1:27017/deeya-invest for a local MongoDB server.');
}
if (/[<>]/.test(mongodbUri) || /@<cluster>|<username>|<password>|<database>/.test(mongodbUri)) {
  throw new Error('MONGODB_URI still contains template placeholders. Replace <username>, <password>, <cluster>, and <database> with the values from MongoDB Atlas.');
}
mongoose.connect(mongodbUri, { serverSelectionTimeoutMS: 10000, maxPoolSize: 10, family: 4 })
  .then(() => {
    console.log('MongoDB connected successfully.');
    const server = app.listen(PORT, () => console.log(`Deeya Invest running at http://localhost:${PORT}`));
    server.on('error', error => {
      if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. The app may already be running at http://localhost:${PORT}.`);
        return process.exitCode = 1;
      }
      console.error('Server failed to start:', error.message);
      process.exitCode = 1;
    });
  })
  .catch(error => { console.error('MongoDB connection failed:', error.message); process.exit(1); });