import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { Pool } from 'pg'
import twilio from 'twilio'
import rateLimit from 'express-rate-limit'
import axios from 'axios'
import { z } from 'zod'

dotenv.config()

const app  = express()
const PORT = process.env.PORT || 4000

// ── DB ──
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

// ── Twilio ──
const smsClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)

// ── Middleware ──
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5173', credentials: true }))
app.use(express.json())

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: { message: 'Too many requests. Try again in 10 minutes.' }
})

// ── DB Migration ──
async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS state_medical_council (
      id                  SERIAL PRIMARY KEY,
      nmr_id              VARCHAR(100) UNIQUE NOT NULL,
      name                VARCHAR(200) NOT NULL,
      phone               VARCHAR(20)  NOT NULL,
      council             VARCHAR(200),
      speciality          VARCHAR(200),
      reg_year            VARCHAR(10),
      qualify_year        VARCHAR(10),
      registration_number INT,
      is_active           BOOLEAN DEFAULT true
    );

    CREATE TABLE IF NOT EXISTS otp_store (
      id         SERIAL PRIMARY KEY,
      nmr_id     VARCHAR(100) NOT NULL,
      otp        VARCHAR(6)   NOT NULL,
      expires_at TIMESTAMPTZ  NOT NULL,
      used       BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    INSERT INTO state_medical_council
      (nmr_id, name, phone, council, speciality, reg_year, qualify_year, registration_number)
    VALUES
      ('MH-2024-00001','Dr. Priya Sharma',  '+919876543210','Maharashtra Medical Council','Cardiology', '2018','2016',100001),
      ('DL-2022-00042','Dr. Arjun Mehta',   '+919123456789','Delhi Medical Council',      'Neurology',  '2022','2020',100042),
      ('KA-2021-00099','Dr. Kavitha Reddy', '+918765432109','Karnataka Medical Council',  'Pediatrics', '2021','2019',100099),
      ('TN-2023-00200','Dr. Rajesh Iyer',   '+917654321098','Tamil Nadu Medical Council', 'Orthopedics','2023','2021',100200),
      ('UP-2020-00310','Dr. Ananya Singh',  '+916543210987','UP Medical Council',         'Dermatology','2020','2018',100310)
    ON CONFLICT (nmr_id) DO NOTHING;
  `)
  console.log('✅ Database ready')
}

// ── Blockchain check ──
async function isNmrOnChain(nmrId: string): Promise<boolean> {
  try {
    const CONTRACT = process.env.CONTRACT_ADDRESS
    const NODE     = process.env.APTOS_NODE_URL || 'https://fullnode.testnet.aptoslabs.com/v1'
    const res = await axios.post(`${NODE}/view`, {
      function: `${CONTRACT}::DoctorRegistryContract::isNMRIDRegister`,
      type_arguments: [],
      arguments: [CONTRACT, nmrId],
    })
    return res.data[0] === true
  } catch { return false }
}

// ── OTP helpers ──
function genOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

async function sendOtp(nmrId: string, phone: string) {
  const otp = genOtp()
  const exp = new Date(Date.now() + 10 * 60 * 1000)
  await pool.query(`UPDATE otp_store SET used=true WHERE nmr_id=$1 AND used=false`, [nmrId])
  await pool.query(`INSERT INTO otp_store (nmr_id,otp,expires_at) VALUES($1,$2,$3)`, [nmrId, otp, exp])
  await smsClient.messages.create({
    body: `MediNex OTP: ${otp} — valid 10 min. Do not share.`,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: phone,
  })
}

async function verifyOtp(nmrId: string, otp: string): Promise<boolean> {
  const r = await pool.query(
    `SELECT id FROM otp_store WHERE nmr_id=$1 AND otp=$2 AND used=false AND expires_at>NOW() LIMIT 1`,
    [nmrId, otp])
  if (!r.rows.length) return false
  await pool.query(`UPDATE otp_store SET used=true WHERE id=$1`, [r.rows[0].id])
  return true
}

// ── Routes ──

app.post('/api/auth/check-nmr', async (req, res) => {
  try {
    const { nmrId } = z.object({ nmrId: z.string().min(1) }).parse(req.body)
    const db = await pool.query(
      `SELECT * FROM state_medical_council WHERE nmr_id=$1 AND is_active=true`, [nmrId])
    if (!db.rows.length)
      return res.json({ status: 'not_found', message: 'NMR ID not registered with any State Medical Council.' })

    const doc  = db.rows[0]
    const info = {
      name: doc.name, council: doc.council, speciality: doc.speciality,
      reg_year: doc.reg_year, qualify_year: doc.qualify_year,
      phone: doc.phone.slice(-4).padStart(doc.phone.length, '*'),
      registration_number: doc.registration_number,
    }
    return res.json({ status: 'council_registered', doctorInfo: info })
  } catch (e: any) {
    return res.status(500).json({ message: e.message })
  }
})

app.post('/api/auth/send-otp', otpLimiter, async (req, res) => {
  try {
    const { nmrId } = z.object({ nmrId: z.string().min(1) }).parse(req.body)
    const db = await pool.query(`SELECT phone FROM state_medical_council WHERE nmr_id=$1`, [nmrId])
    if (!db.rows.length) return res.status(404).json({ message: 'Doctor not found.' })
    await sendOtp(nmrId, db.rows[0].phone)
    res.json({ message: 'OTP sent.' })
  } catch (e: any) {
    res.status(500).json({ message: e.message })
  }
})

app.post('/api/auth/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { nmrId, otp } = z.object({ nmrId: z.string(), otp: z.string().length(6) }).parse(req.body)
    const ok = await verifyOtp(nmrId, otp)
    if (!ok) return res.status(400).json({ message: 'Invalid or expired OTP.' })
    res.json({ message: 'OTP verified.' })
  } catch (e: any) {
    res.status(500).json({ message: e.message })
  }
})

app.get('/api/auth/doctor-info/:nmrId', async (req, res) => {
  try {
    const db = await pool.query(
      `SELECT nmr_id,name,council,speciality,reg_year,qualify_year FROM state_medical_council WHERE nmr_id=$1`,
      [req.params.nmrId])
    if (!db.rows.length) return res.status(404).json({ message: 'Not found.' })
    res.json({ doctor: db.rows[0] })
  } catch (e: any) {
    res.status(500).json({ message: e.message })
  }
})

app.get('/health', (_req, res) => res.json({ ok: true }))

// ── Start ──
migrate()
  .then(() => app.listen(PORT, () => console.log(`🚀 Backend running on http://localhost:${PORT}`)))
  .catch(e => { console.error(e); process.exit(1) })
  