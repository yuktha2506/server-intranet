/**
 * MT CNC-Group API routes backed entirely by in-memory JavaScript data.
 * Data changes reset when the Node process restarts.
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const DEFAULT_ADMIN_HASH = '$2b$12$PWf8L6eNV8KtugVoWf6WlOfVL1WZX9uJ7ELv/HmlvM8BWvzOE6wnu';
const DEFAULT_EMPLOYEE_HASH = '$2b$12$sR28Ox9361Gf9qoaj6TzM.XPvOPVeB6eiBLcRoSoa.HyML1f3IHV.';
const ADMIN_PASSWORD_HASH = DEFAULT_ADMIN_HASH;
const EMPLOYEE_PASSWORD_HASH = process.env.EMPLOYEE_PASSWORD_HASH || DEFAULT_EMPLOYEE_HASH;
if (process.env.NODE_ENV === 'production' && !process.env.EMPLOYEE_PASSWORD_HASH) {
  throw new Error('Production requires an EMPLOYEE_PASSWORD_HASH override.');
}
for (const hash of [ADMIN_PASSWORD_HASH, EMPLOYEE_PASSWORD_HASH]) {
  if (!/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/.test(hash)) throw new Error('Static account password settings must be bcrypt hashes.');
}
const STATIC_ACCOUNTS = [
  { id: 'static-admin', emp_id: 'Admin', username: 'Admin', full_name: 'Admin', role: 'admin', status: 'active', password_hash: ADMIN_PASSWORD_HASH },
  { id: 'static-employee', emp_id: '00000101', username: '00000101', full_name: 'Employee', role: 'employee', status: 'active', password_hash: EMPLOYEE_PASSWORD_HASH }
];
const staticAccountById = new Map(STATIC_ACCOUNTS.map((account) => [account.id, account]));
const PHONE_DIRECTORY_SOURCE = [
  {
    "department": "Accounts",
    "names": "Mr. Murugan / Mr. Vinoth Kumar",
    "phone_ext": "2001"
  },
  {
    "department": "Accounts",
    "names": "Surendran R / Vignesh G B",
    "phone_ext": "2002"
  },
  {
    "department": "Marketing",
    "names": "Mr. Muthu / Mrs. Rohini",
    "phone_ext": "2003"
  },
  {
    "department": "Design",
    "names": "Vinoth Kumar / Ramesh",
    "phone_ext": "2004"
  },
  {
    "department": "Sourcing",
    "names": "Mr. Ramamoorthy",
    "phone_ext": "2005"
  },
  {
    "department": "Purchase",
    "names": "Thyagarajulu N / Santhosh Rao S",
    "phone_ext": "2006"
  },
  {
    "department": "HRD",
    "names": "Mrs. Vijayarani",
    "phone_ext": "2007"
  },
  {
    "department": "HR & Admin",
    "names": "Mr. Prasanth Rajendran",
    "phone_ext": "2008"
  },
  {
    "department": "QAD Head",
    "names": "Mr. Mathaiyan Ayyandurai",
    "phone_ext": "2009"
  },
  {
    "department": "Finance Head",
    "names": "Mr. Ganesa Subramanian",
    "phone_ext": "2010"
  },
  {
    "department": "CFO Head",
    "names": "Mr.",
    "phone_ext": "2011"
  },
  {
    "department": "Marketing Head",
    "names": "Mr. Naveen Tilak HG",
    "phone_ext": "2012"
  },
  {
    "department": "HR Head",
    "names": "Dhandabani S",
    "phone_ext": "2013"
  },
  {
    "department": "Profit Agro Head",
    "names": "Mr. Prabu",
    "phone_ext": "2014"
  },
  {
    "department": "HR & Admin",
    "names": "Deepthi Muralibabu M",
    "phone_ext": "2018"
  },
  {
    "department": "Admin & SCM Head",
    "names": "Mr. Velappan R",
    "phone_ext": "2019"
  },
  {
    "department": "Chief Executive Officer",
    "names": "Mr. Narasimman L",
    "phone_ext": "2020"
  },
  {
    "department": "Executive Director",
    "names": "Mr. Ravi P",
    "phone_ext": "2021"
  },
  {
    "department": "IT Head",
    "names": "Mr. Selvaraj",
    "phone_ext": "2022"
  },
  {
    "department": "Joint Director",
    "names": "Mr. Vignesh Muralibabu",
    "phone_ext": "2023"
  },
  {
    "department": "Joint Director",
    "names": "Mr. Josepaul Johnson",
    "phone_ext": "2024"
  },
  {
    "department": "Director",
    "names": "Mr. Muralibabu",
    "phone_ext": "2025"
  },
  {
    "department": "Director",
    "names": "Mr. Johnson Paul",
    "phone_ext": "2026"
  },
  {
    "department": "Plant Head",
    "names": "Mr. Dhugaram",
    "phone_ext": "2028"
  },
  {
    "department": "Store",
    "names": "Mr. Kannadasan",
    "phone_ext": "2029"
  },
  {
    "department": "Maintenance / Quality",
    "names": "Mr. Madesh / Ashok",
    "phone_ext": "2030"
  },
  {
    "department": "Production Office",
    "names": "Production / Store /PPC Common",
    "phone_ext": "2031"
  },
  {
    "department": "Security Gate",
    "names": "Mr. Deepak",
    "phone_ext": "2032"
  },
  {
    "department": "CMM",
    "names": "Mr. Balakannan",
    "phone_ext": "2033"
  },
  {
    "department": "Canteen",
    "names": "Mrs. Vasanthi / Rathanamma",
    "phone_ext": "2034"
  },
  {
    "department": "Department",
    "names": "Name",
    "phone_ext": "Tel.No"
  },
  {
    "department": "Engineering",
    "names": "Mr. Manukumar T M / Mr. Chiranjeevi",
    "phone_ext": "2001"
  },
  {
    "department": "Marketing",
    "names": "Mr. Sadeshkumar",
    "phone_ext": "2002"
  },
  {
    "department": "Marketing",
    "names": "Mr. Purushotham A Athni / Mr. Vignesh D N",
    "phone_ext": "2003"
  },
  {
    "department": "Design & Development",
    "names": "Mr. Promod",
    "phone_ext": "2004"
  },
  {
    "department": "QMS",
    "names": "Mrs. Thenmozhi S",
    "phone_ext": "2006"
  }
];
const DEPARTMENT_EMAIL_SOURCE = [
  {
    "department": "ACCOUNTS",
    "email": "accounts-unit2@microtechcnc.in",
    "name": "Accounts-Unit2"
  },
  {
    "department": "ACCOUNTS",
    "email": "accounts-unit1@microtechcnc.in",
    "name": "Accounts Unit1"
  },
  {
    "department": "PRODUCTION",
    "email": "production-unit2@microtechcnc.in",
    "name": "Anandababu K"
  },
  {
    "department": "QUALITY",
    "email": "quality-unit2@microtechcnc.in",
    "name": "Arun"
  },
  {
    "department": "QUALITY",
    "email": "babu.t@microtechcnc.in",
    "name": "Babu T"
  },
  {
    "department": "ACCOUNTS",
    "email": "cfo@microtechcnc.in",
    "name": "Cfo"
  },
  {
    "department": "PRODUCTION",
    "email": "cncprogram@microtechcnc.in",
    "name": "Cncprogram"
  },
  {
    "department": "MARKETING",
    "email": "vignesh.dn@microtechcnc.in",
    "name": "D N Vignesh"
  },
  {
    "department": "MANAGEMENT",
    "email": "deepthimuralibabu@microtechcnc.in",
    "name": "Deepthi Muralibabu"
  },
  {
    "department": "STORES",
    "email": "stores-unit4@microtechcnc.in",
    "name": "Dhileeban M"
  },
  {
    "department": "PALNT HEAD",
    "email": "dhugaram@microtechcnc.in",
    "name": "Dhugaram S"
  },
  {
    "department": "HR",
    "email": "recruitment@microtechcnc.in",
    "name": "Elango Rajalingam"
  },
  {
    "department": "PRODUCTION",
    "email": "production-unit3@microtechcnc.in",
    "name": "Esaki Raja P"
  },
  {
    "department": "ACCOUNTS",
    "email": "finance-corp@microtechcnc.in",
    "name": "Ganesa Subramanian G V"
  },
  {
    "department": "GATE",
    "email": "gate@microtechcnc.in",
    "name": "Gate"
  },
  {
    "department": "HR",
    "email": "hrd-unit1@microtechcnc.in",
    "name": "Hrd-Unit1"
  },
  {
    "department": "HR",
    "email": "hrd-unit3@microtechcnc.in",
    "name": "Hrd-Unit3"
  },
  {
    "department": "TRAINEE",
    "email": "interns@microtechcnc.in",
    "name": "Interns"
  },
  {
    "department": "HR",
    "email": "microtechcnc-unit3@microtechcnc.in",
    "name": "Jayabalakrishan"
  },
  {
    "department": "MANAGEMENT",
    "email": "johnsonpaul@microtechcnc.in",
    "name": "Johnson Pul"
  },
  {
    "department": "NPD",
    "email": "toolroom-unit1@microtechcnc.in",
    "name": "Kalaiarasan G"
  },
  {
    "department": "QUALITY",
    "email": "quality-fab@microtechcnc.in",
    "name": "Kamalakannan S"
  },
  {
    "department": "PRODUCTION",
    "email": "presshop-unit3@microtechcnc.in",
    "name": "Kandeepan K"
  },
  {
    "department": "QUALITY",
    "email": "kkannan@microtechcnc.in",
    "name": "Kannan K"
  },
  {
    "department": "PRODUCTION",
    "email": "skmoorthy@microtechcnc.in",
    "name": "Krishnamoorthy S"
  },
  {
    "department": "PALNT HEAD",
    "email": "krishnan.p@microtechcnc.in",
    "name": "Krishnan P"
  },
  {
    "department": "QUALITY",
    "email": "kumar@microtechcnc.in",
    "name": "Kumar N"
  },
  {
    "department": "STORES",
    "email": "stores-unit2@microtechcnc.in",
    "name": "Lakshmi Narayanan M"
  },
  {
    "department": "PRODUCTION PLANNING",
    "email": "ppmc-unit1@microtechcnc.in",
    "name": "Logathiban K"
  },
  {
    "department": "MAINTENANCE",
    "email": "maintenance-unit1@microtechcnc.in",
    "name": "Madesh K M"
  },
  {
    "department": "MARKETING",
    "email": "costing@microtechcnc.in",
    "name": "Magesh Kumar"
  },
  {
    "department": "MAINTENANCE",
    "email": "maintenance-unit4@microtechcnc.in",
    "name": "Maintenance-Unit4"
  },
  {
    "department": "PRODUCTION PLANNING",
    "email": "ppmc-unit3@microtechcnc.in",
    "name": "Manikandan E"
  },
  {
    "department": "PROCESS ENGINEERING",
    "email": "manukumar.tm@microtechcnc.in",
    "name": "Manukumar.Tm"
  },
  {
    "department": "MARKETING",
    "email": "marketing@microtechcnc.in",
    "name": "Marketing"
  },
  {
    "department": "MARKETING",
    "email": "marketing-unit3@microtechcnc.in",
    "name": "Marketing Unit3"
  },
  {
    "department": "MICROTECHCNC",
    "email": "microtechcnc@microtechcnc.in",
    "name": "Microtechcnc"
  },
  {
    "department": "MICROTECHCNC",
    "email": "microtechcnc-unit4@microtechcnc.in",
    "name": "Microtechcnc-Unit4"
  },
  {
    "department": "MANAGEMENT",
    "email": "muralibabu@microtechcnc.in",
    "name": "Muralibabu G"
  },
  {
    "department": "MARKETING",
    "email": "rfq@microtechcnc.in",
    "name": "Muthuraman"
  },
  {
    "department": "CEO",
    "email": "narasimman.l@microtechcnc.in",
    "name": "Narasimman L"
  },
  {
    "department": "MARKETING",
    "email": "naveen.tilak@microtechcnc.in",
    "name": "Naveen Tilak"
  },
  {
    "department": "NPD",
    "email": "npd-unit1@microtechcnc.in",
    "name": "Npd Unit1"
  },
  {
    "department": "NPD",
    "email": "npd-unit3@microtechcnc.in",
    "name": "Npd Unit3"
  },
  {
    "department": "NPD",
    "email": "npdquality-unit3@microtechcnc.in",
    "name": "Npdquality-Unit3"
  },
  {
    "department": "PRODUCTION",
    "email": "palani@microtechcnc.in",
    "name": "Pazhani T"
  },
  {
    "department": "PROCESS ENGINEERING",
    "email": "ped@microtechcnc.in",
    "name": "Ped"
  },
  {
    "department": "STORES",
    "email": "stores-unit3@microtechcnc.in",
    "name": "Prakash E"
  },
  {
    "department": "HR",
    "email": "hrd@microtechcnc.in",
    "name": "Prasanth R"
  },
  {
    "department": "QUALITY",
    "email": "product-qa@microtechcnc.in",
    "name": "Product-Qa"
  },
  {
    "department": "PRODUCTION",
    "email": "product-unit3@microtechcnc.in",
    "name": "Product Unit3"
  },
  {
    "department": "PRODUCTION",
    "email": "production-unit1@microtechcnc.in",
    "name": "Production-Unit1"
  },
  {
    "department": "PURCHASE",
    "email": "purchase-unit3@microtechcnc.in",
    "name": "Purchase-Unit3"
  },
  {
    "department": "MARKETING",
    "email": "purushotham.Athni@microtechcnc.in",
    "name": "Purushotham Athni"
  },
  {
    "department": "QUALITY",
    "email": "qms-corp@microtechcnc.in",
    "name": "Qms Corp"
  },
  {
    "department": "QUALITY",
    "email": "quality-unit1@microtechcnc.in",
    "name": "Quality-Unit1"
  },
  {
    "department": "QUALITY",
    "email": "quality-unit4@microtechcnc.in",
    "name": "Quality-Unit4"
  },
  {
    "department": "MAINTENANCE",
    "email": "maintenance-unit3@microtechcnc.in",
    "name": "Raji B"
  },
  {
    "department": "NPD",
    "email": "raju.l@microtechcnc.in",
    "name": "Raju L"
  },
  {
    "department": "PURCHASE",
    "email": "sourcing@microtechcnc.in",
    "name": "Ramamoorthy R"
  },
  {
    "department": "NPD",
    "email": "ramesh.c@microtechcnc.in",
    "name": "Ramesh C"
  },
  {
    "department": "EXECUTIVE DIRECTOR",
    "email": "ravi@microtechcnc.in",
    "name": "Ravi P"
  },
  {
    "department": "ACCOUNTS",
    "email": "acs@microtechcnc.in",
    "name": "Rohini Ramanathan"
  },
  {
    "department": "PRODUCTION PLANNING",
    "email": "despatch-unit3@microtechcnc.in",
    "name": "Sakthivel S"
  },
  {
    "department": "PURCHASE",
    "email": "purchase-unit4@microtechcnc.in",
    "name": "Santhosh Rao S"
  },
  {
    "department": "MAINTENANCE",
    "email": "maintenance-unit2@microtechcnc.in",
    "name": "Saravanan R"
  },
  {
    "department": "NPD",
    "email": "sathishkumar.g@microtechcnc.in",
    "name": "Sathishkumar G"
  },
  {
    "department": "IT",
    "email": "itadmin@microtechcnc.in",
    "name": "Selvaraj A - It"
  },
  {
    "department": "STORES",
    "email": "stores-unit1@microtechcnc.in",
    "name": "Stores-Unit1"
  },
  {
    "department": "QUALITY",
    "email": "teekaraman@microtechcnc.in",
    "name": "Teekaraman"
  },
  {
    "department": "MANAGEMENT",
    "email": "teenamariya@microtechcnc.in",
    "name": "Teena Mariya"
  },
  {
    "department": "QUALITY",
    "email": "quality-unit3@microtechcnc.in",
    "name": "Thangaraj"
  },
  {
    "department": "PURCHASE",
    "email": "thyagarajulu.n@microtechcnc.in",
    "name": "Thyagarajulu N"
  },
  {
    "department": "PURCHASE",
    "email": "purchase-unit1@microtechcnc.in",
    "name": "Uma Devi S"
  },
  {
    "department": "ACCOUNTS",
    "email": "accounts-unit3@microtechcnc.in",
    "name": "Vignesh G B"
  },
  {
    "department": "MANAGEMENT",
    "email": "vignesh.m@microtechcnc.in",
    "name": "Vignesh Muralibabu"
  },
  {
    "department": "PLANT HEAD",
    "email": "vinoth@microtechcnc.in",
    "name": "Vinoth V"
  },
  {
    "department": "PRODUCTION",
    "email": "machineshop-unit3@microtechcnc.in",
    "name": "Vinoth V"
  },
  {
    "department": "PRODUCTION",
    "email": "weldshop-unit3@microtechcnc.in",
    "name": "Weldshop-Unit3"
  },
  {
    "department": "MANAGEMENT",
    "email": "josepaul@microtechcnc.in",
    "name": "Josepaul"
  }
];
const normalizeDirectoryName = (value) => String(value || '').toLowerCase().replace(/\b(mr|mrs|ms|miss|dr)\b\.?/g, '').replace(/[^a-z0-9]/g, '');
const STATIC_EMPLOYEES = (() => {
  const contacts = [];
  const byName = new Map();
  const addContact = ({ name, department, phone_ext = '', email = '' }) => {
    const cleanName = String(name || '').replace(/\s+/g, ' ').trim();
    if (!cleanName || /\bcommon\b/i.test(cleanName) || /^mr\.?$/i.test(cleanName)) return;
    const key = normalizeDirectoryName(cleanName);
    const existing = byName.get(key);
    if (existing) {
      if (!existing.department && department) existing.department = department;
      if (phone_ext && !existing.phone_ext) existing.phone_ext = phone_ext;
      if (email && !existing.email.split(/[,;]\s*/).includes(email)) existing.email = [existing.email, email].filter(Boolean).join('; ');
      return;
    }
    const contact = { id: contacts.length + 1, emp_id: '', name: cleanName, designation: '', department: department || '', phone_ext, shift: '', email };
    contacts.push(contact);
    byName.set(key, contact);
  };
  for (const row of PHONE_DIRECTORY_SOURCE) {
    if (/common/i.test(row.names) || row.department === 'Department') continue;
    for (const name of row.names.split(/\s*\/\s*/)) addContact({ name, department: row.department, phone_ext: row.phone_ext });
  }
  for (const row of DEPARTMENT_EMAIL_SOURCE) addContact(row);
  return contacts;
})();
const MEMORY = {
  board: {
    last_incident_date: '2025-11-10',
    incident_free_target: 365,
    on_time_delivery: '98.5%',
    delivery_note: 'November Target Achieved',
    machines_down: '0 of 24',
    machines_note: 'All 24 machines operating at peak capacity'
  },
  announcements: [
    { id: 1, category: 'Safety', headline: 'Chip conveyor guards must stay closed during cycle', body: 'Operators must not open the chip conveyor guard while a program is running. Supervisors will check guards at each shift start.', is_pinned: 1, posted_date: '2026-11-09', created_by: 'static-admin' },
    { id: 2, category: 'Production', headline: 'Night shift moves to a 10 PM start from 1 December', body: 'Individual rosters will be shared by department heads.', is_pinned: 0, posted_date: '2026-11-08', created_by: 'static-admin' },
    { id: 3, category: 'Maintenance', headline: 'Scheduled preventive maintenance for VMC lines this Saturday', body: 'Lines 2 and 4 will be offline from 14:00 to 18:00 for hydraulic fluid flush and filter replacement.', is_pinned: 0, posted_date: '2026-11-07', created_by: 'static-admin' },
    { id: 4, category: 'Quality', headline: 'Zero-defect initiative audit scheduled for next week', body: 'All quality inspection checklists must be updated at workstations before 15 November.', is_pinned: 0, posted_date: '2026-11-06', created_by: 'static-admin' }
  ],
  events: [
    { id: 1, event_date: '2026-11-14', title: 'Quarterly Safety Committee Review', place_and_time: 'Main Conference Hall, 10:00 AM', created_by: 'static-admin' },
    { id: 2, event_date: '2026-11-18', title: '5S Shop Floor Excellence Walk', place_and_time: 'Shop Floor Bays 1-4, 02:30 PM', created_by: 'static-admin' },
    { id: 3, event_date: '2026-11-25', title: 'Blood Donation Camp', place_and_time: 'Employee Wellness Center, 09:00 AM - 04:00 PM', created_by: 'static-admin' },
    { id: 4, event_date: '2026-12-05', title: 'Annual Plant Townhall & Awards', place_and_time: 'Auditorium & Live Stream, 03:00 PM', created_by: 'static-admin' }
  ],
  tickets: [], suggestions: [], holidays: [
    { id: 1, holiday_date: '2026-12-25', name: 'Christmas Day', day_name: 'Friday' },
    { id: 2, holiday_date: '2027-01-01', name: "New Year's Day", day_name: 'Friday' },
    { id: 3, holiday_date: '2027-01-14', name: 'Pongal', day_name: 'Thursday' },
    { id: 4, holiday_date: '2027-01-26', name: 'Republic Day', day_name: 'Tuesday' },
    { id: 5, holiday_date: '2027-03-22', name: 'Holi', day_name: 'Monday' },
    { id: 6, holiday_date: '2027-05-01', name: 'May Day', day_name: 'Saturday' },
    { id: 7, holiday_date: '2027-08-15', name: 'Independence Day', day_name: 'Sunday' },
    { id: 8, holiday_date: '2027-10-02', name: 'Gandhi Jayanti', day_name: 'Saturday' },
    { id: 9, holiday_date: '2027-10-20', name: 'Dussehra', day_name: 'Wednesday' },
    { id: 10, holiday_date: '2027-11-08', name: 'Diwali', day_name: 'Monday' }
  ], links: []
};
const ASSET_COLUMNS = [
  "User Id",
  "Name",
  "Endpoint Name",
  "IP Address",
  "Endpoint Status",
  "Roaming Service",
  "Domain Name",
  "Group Name",
  "User Name",
  "Policy",
  "Policy Status",
  "Virus DB Date (GMT+5:30)",
  "Last Connected",
  "Last Scanned",
  "MAC Address",
  "Serial Number",
  "Client Version",
  "Operating System",
  "DLP",
  "AV Status",
  "EDR Sensor Version"
];
const STATIC_ASSETS = [
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION3-D1",
    "IP Address": "10.24.3.4",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PRODUCTION3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:14]",
    "Last Scanned": "02 Nov 2026 [12:00:22]",
    "MAC Address": "8C-EC-4B-60-0E-F6",
    "Serial Number": "1Y9GGP2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL01-L1",
    "IP Address": "192.168.1.41",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MPIPL-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "11 Nov 2026 [16:55:45]",
    "Last Scanned": "10 Oct 2026 [14:01:15]",
    "MAC Address": "E4-0D-36-12-54-CB",
    "Serial Number": "5CD337GV05",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "NPD3-D3",
    "IP Address": "10.24.3.97",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "NPD3-D3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:29]",
    "Last Scanned": "07 Nov 2026 [12:21:35]",
    "MAC Address": "98-90-96-C9-DB-D5",
    "Serial Number": "G0WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINT1-L1",
    "IP Address": "172.32.2.79",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "MAINTM1-L1",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [00:02:17]",
    "Last Connected": "13 Nov 2026 [08:56:37]",
    "Last Scanned": "17 Oct 2026 [13:10:48]",
    "MAC Address": "B0-C0-90-C6-6E-E4",
    "Serial Number": "GJ695C2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PEDCORP-NB1",
    "IP Address": "10.24.1.230",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CORPMKT-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [18:29:05]",
    "Last Scanned": "31 Oct 2026 [12:53:28]",
    "MAC Address": "F8-FE-5E-D4-B8-EF",
    "Serial Number": "5CD411JN8K",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "RFQU1-L2",
    "IP Address": "10.24.1.64",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "RFQU1-L2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:36]",
    "Last Scanned": "24 Oct 2026 [13:56:14]",
    "MAC Address": "9C-C7-D3-65-B6-FC",
    "Serial Number": "5CG5343VS9",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U4MFGHEAD-L2",
    "IP Address": "172.32.2.80",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "U4MFGHEAD-L2",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "12 Nov 2026 [19:56:10]",
    "Last Scanned": "24 Oct 2026 [11:29:05]",
    "MAC Address": "9C-C7-D3-52-D4-16",
    "Serial Number": "5CG5343VYP",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U2MFGHEAD-L3",
    "IP Address": "10.24.2.120",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "U2MFGHEAD-L3",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:59]",
    "Last Scanned": "11 Nov 2026 [12:42:01]",
    "MAC Address": "9C-C7-D3-4F-E2-D6",
    "Serial Number": "5CG5343T7Z",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DEVELOPMENT",
    "IP Address": "10.24.3.98",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "DEVELOPMENT",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:23]",
    "Last Scanned": "03 Oct 2026 [14:35:04]",
    "MAC Address": "40-ED-00-21-DE-BB",
    "Serial Number": "FRPTDV2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HP11-HYPERV-RDP",
    "IP Address": "172.32.2.14",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->RDP Server",
    "User Name": "Administrator",
    "Policy": "RDP Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:04]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-02-0B-08",
    "Serial Number": "8997-2588-8871-0251-7243-0556-65",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORES4-D2",
    "IP Address": "10.24.1.229",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORES4-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [09:32:13]",
    "Last Scanned": "31 Oct 2026 [12:15:59]",
    "MAC Address": "9C-B1-50-56-C5-D9",
    "Serial Number": "HH41P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADM1-D2",
    "IP Address": "10.24.1.169",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "QADM1-D2",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "09 Oct 2026 [14:25:58]",
    "Last Connected": "09 Oct 2026 [16:34:05]",
    "Last Scanned": "07 Oct 2026 [15:59:57]",
    "MAC Address": "98-90-96-C9-D6-42",
    "Serial Number": "G1WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-PDC",
    "IP Address": "10.24.1.25",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "MTG-MT-RDP1$",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:23]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-BB-67-00",
    "Serial Number": "9673-8510-5309-4864-4933-0245-19",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CFO1-L1",
    "IP Address": "10.24.1.131",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CFO-L1",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "19 Oct 2026 [08:41:05]",
    "Last Connected": "19 Oct 2026 [12:08:49]",
    "Last Scanned": "10 Oct 2026 [12:18:01]",
    "MAC Address": "C8-58-C0-82-E7-90",
    "Serial Number": "69P8WZ2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CNCPROGRAM1-D1",
    "IP Address": "10.24.1.75",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CNCPROGRAM-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:01:59]",
    "Last Scanned": "31 Oct 2026 [12:10:02]",
    "MAC Address": "84-5C-31-FF-FA-2C",
    "Serial Number": "F3P6R24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DESPATCH3-D1",
    "IP Address": "10.24.3.51",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "DESPATCH3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:52]",
    "Last Scanned": "31 Oct 2026 [12:53:08]",
    "MAC Address": "8C-EC-4B-60-4C-4F",
    "Serial Number": "1XGNGP2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-IT",
    "IP Address": "10.24.1.28",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:04]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-01",
    "Serial Number": "4748-3613-2226-5593-2788-6448-12",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-Hyperv-21",
    "IP Address": "10.24.1.22",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:34]",
    "Last Scanned": "-",
    "MAC Address": "14-23-F2-79-4D-0C",
    "Serial Number": "CNXD1B01M3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ADMIN3-D1",
    "IP Address": "10.24.3.76",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ADMIN3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [17:35:36]",
    "Last Scanned": "17 Oct 2026 [12:40:51]",
    "MAC Address": "64-00-6A-14-BD-7A",
    "Serial Number": "3J6K882",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HP11-VM-ADC",
    "IP Address": "172.32.2.25",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:07]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-02-0B-0B",
    "Serial Number": "8580-5155-6985-7725-9393-2825-71",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QUALITY3-D1",
    "IP Address": "10.24.3.57",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QUALITY3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:09]",
    "Last Scanned": "07 Nov 2026 [12:40:17]",
    "MAC Address": "54-48-10-FF-D9-C0",
    "Serial Number": "18QJXH2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "COSTING1-L1",
    "IP Address": "10.24.1.120",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "U1COSTING-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:56]",
    "Last Scanned": "31 Oct 2026 [12:40:47]",
    "MAC Address": "E4-A4-71-2E-B1-2A",
    "Serial Number": "CCMXKC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "NPD3-D5",
    "IP Address": "10.24.3.70",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "NPD3-D5",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:00]",
    "Last Scanned": "31 Oct 2026 [12:19:50]",
    "MAC Address": "E4-54-E8-CB-16-A5",
    "Serial Number": "11MXJ23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-Hyperv-20",
    "IP Address": "10.24.1.23",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:57]",
    "Last Scanned": "-",
    "MAC Address": "14-23-F2-74-2A-BF",
    "Serial Number": "CNXD1B018Y",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADU1-NB1",
    "IP Address": "10.24.1.232",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "FINANCE1-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:33]",
    "Last Scanned": "17 Oct 2026 [12:44:07]",
    "MAC Address": "F8-FE-5E-D2-6A-27",
    "Serial Number": "5CD411JN3H",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "LASERCUTTING3-D1",
    "IP Address": "10.24.3.100",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "LASERCUTTING3-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:15]",
    "Last Scanned": "31 Oct 2026 [12:33:13]",
    "MAC Address": "00-BE-43-B7-D4-9E",
    "Serial Number": "D7DNQR3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-EPS",
    "IP Address": "10.24.1.102",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:18]",
    "Last Scanned": "10 Oct 2026 [12:17:19]",
    "MAC Address": "00-15-5D-BB-67-0D",
    "Serial Number": "8465-5477-0382-0525-9968-4557-95",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SCM-ADMIN-L1",
    "IP Address": "10.24.1.134",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CORPQAD-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:32]",
    "Last Scanned": "31 Oct 2026 [12:33:45]",
    "MAC Address": "50-5A-65-B2-D2-C7",
    "Serial Number": "5CD2510PCZ",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORES3-D1",
    "IP Address": "10.24.3.27",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORES3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:44]",
    "Last Scanned": "31 Oct 2026 [12:33:35]",
    "MAC Address": "8C-EC-4B-CB-9F-11",
    "Serial Number": "B7JV3W2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MKT3-L2",
    "IP Address": "10.24.3.136",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MKT3-NB2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [09:59:50]",
    "Last Scanned": "31 Oct 2026 [12:36:07]",
    "MAC Address": "08-F9-7E-58-5D-73",
    "Serial Number": "54KNVF4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SELVARAJ-IT",
    "IP Address": "10.24.1.99",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "adminse",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:29]",
    "Last Scanned": "14 Aug 2026 [00:29:23]",
    "MAC Address": "00-BE-43-8D-E1-93",
    "Serial Number": "23C7SN3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "RFQ-L1",
    "IP Address": "10.24.1.122",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "RFQ1-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:13]",
    "Last Scanned": "31 Oct 2026 [12:26:19]",
    "MAC Address": "28-3A-4D-53-5A-9B",
    "Serial Number": "F9TMWS2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PURCHASE1_L1",
    "IP Address": "10.24.1.199",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PURCHASE1-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "13 Nov 2026 [09:37:59]",
    "Last Scanned": "12 Sep 2026 [14:36:20]",
    "MAC Address": "0C-96-E6-40-C4-3F",
    "Serial Number": "2BC4XS2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SISRVR",
    "IP Address": "172.32.2.96",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:30]",
    "Last Scanned": "-",
    "MAC Address": "00-0C-29-7F-E1-81",
    "Serial Number": "VMware-56 4d 5b 4e 74 c2 b5 cf-19 32 c6 29 f7 7f e1 81",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL4-D4",
    "IP Address": "192.168.1.10",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "MPIPL-D4",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [09:55:45]",
    "Last Scanned": "19 Sep 2026 [12:32:39]",
    "MAC Address": "98-90-96-C9-DA-7D",
    "Serial Number": "HWVR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U3PHD01-L1",
    "IP Address": "10.24.3.127",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll GDrive",
    "User Name": "Admin",
    "Policy": "BlockAll GDrive",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:48]",
    "Last Scanned": "31 Oct 2026 [12:24:31]",
    "MAC Address": "F8-FE-5E-D4-AA-08",
    "Serial Number": "5CD411JN61",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION3-D2",
    "IP Address": "10.24.3.58",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PRODUCTION3-D2",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "15 Oct 2026 [08:28:39]",
    "Last Connected": "15 Oct 2026 [14:42:01]",
    "Last Scanned": "10 Oct 2026 [12:32:41]",
    "MAC Address": "34-17-EB-BA-C4-C2",
    "Serial Number": "CKCSH32",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ASC1-L1",
    "IP Address": "192.168.1.106",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACS-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "11 Nov 2026 [19:50:45]",
    "Last Scanned": "19 Sep 2026 [14:31:54]",
    "MAC Address": "C8-58-C0-82-BC-3E",
    "Serial Number": "2BP8WZ2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRDU1-L3",
    "IP Address": "10.24.1.177",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "NPD1-L3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:06]",
    "Last Scanned": "03 Oct 2026 [14:28:50]",
    "MAC Address": "A8-E2-91-F0-BA-00",
    "Serial Number": "5CG514039F",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U4PLNTMGR-NB1",
    "IP Address": "10.24.1.233",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "PLANTMGR4-NB1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [08:47:35]",
    "Last Connected": "12 Nov 2026 [13:04:05]",
    "Last Scanned": "-",
    "MAC Address": "F8-FE-5E-D4-8D-D4",
    "Serial Number": "5CD411JN4T",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTS1-D5",
    "IP Address": "10.24.1.40",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS1-D5",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:18]",
    "Last Scanned": "31 Oct 2026 [12:25:39]",
    "MAC Address": "20-88-10-70-F0-0D",
    "Serial Number": "J9YDWY3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PEDU1-NB2",
    "IP Address": "172.32.2.88",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PED-NB2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:11]",
    "Last Scanned": "31 Oct 2026 [14:33:09]",
    "MAC Address": "08-F9-7E-58-62-EB",
    "Serial Number": "79GNVF4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORESU1-D2",
    "IP Address": "10.24.1.71",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORES1-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:15]",
    "Last Scanned": "31 Oct 2026 [12:15:09]",
    "MAC Address": "9C-67-D6-6B-6D-22",
    "Serial Number": "52P0P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-Hyperv-11",
    "IP Address": "172.32.2.11",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:52]",
    "Last Scanned": "-",
    "MAC Address": "58-20-B1-EA-DC-00",
    "Serial Number": "",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U1NPD-L1",
    "IP Address": "10.24.1.136",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "U1NPD-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:03]",
    "Last Scanned": "31 Oct 2026 [12:44:19]",
    "MAC Address": "E4-A4-71-2E-B0-3F",
    "Serial Number": "GB5YKC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U4MFGHEAD-L1",
    "IP Address": "172.32.2.84",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "U4MFGHEAD-L1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "13 Nov 2026 [10:02:11]",
    "Last Scanned": "02 Jul 2026 [12:58:23]",
    "MAC Address": "F8-FE-5E-D4-8D-3E",
    "Serial Number": "5CD411JN4V",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "BHCORP-NB1",
    "IP Address": "10.24.1.59",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "BHCORP-NB1",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [16:58:28]",
    "Last Scanned": "15 Oct 2026 [14:37:31]",
    "MAC Address": "AC-19-8E-D1-D1-BB",
    "Serial Number": "5CD3231DL5",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MARKETING3-D1",
    "IP Address": "10.24.3.121",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Default",
    "User Name": "WELDING3-D1",
    "Policy": "Default_EPP",
    "Policy Status": "Not Published",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [18:13:27]",
    "Last Scanned": "31 Oct 2026 [12:51:01]",
    "MAC Address": "D4-BE-D9-91-AD-81",
    "Serial Number": "GBMRWQ1",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MURALIBABU-NB1",
    "IP Address": "172.32.2.94",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "MURALIBABU-L1",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [09:57:03]",
    "Last Scanned": "14 Aug 2026 [11:33:36]",
    "MAC Address": "28-11-A8-43-F2-AB",
    "Serial Number": "5CD1462S4F",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION1-D1",
    "IP Address": "10.24.1.73",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PRODUCTION1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:22]",
    "Last Scanned": "31 Oct 2026 [12:10:39]",
    "MAC Address": "9C-67-D6-6E-03-34",
    "Serial Number": "219ZN24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "NPDu3-d1",
    "IP Address": "10.24.3.71",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "NPD3-D4",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:50]",
    "Last Scanned": "31 Oct 2026 [12:30:04]",
    "MAC Address": "64-00-6A-7B-9D-9A",
    "Serial Number": "1YQHH92",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SCM3-D1",
    "IP Address": "10.24.3.123",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "SCM3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:03:05]",
    "Last Scanned": "07 Nov 2026 [14:09:08]",
    "MAC Address": "8C-EC-4B-6F-6E-E7",
    "Serial Number": "HST1N62",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 8.1 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION2A-D1",
    "IP Address": "192.168.1.5",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "Production2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "10 Oct 2026 [12:36:24]",
    "MAC Address": "50-9A-4C-38-D3-46",
    "Serial Number": "8DJDZL2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRDU1-D1",
    "IP Address": "10.24.1.147",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "HRDU1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:00:46]",
    "Last Scanned": "31 Oct 2026 [12:15:38]",
    "MAC Address": "98-90-96-C9-D6-C4",
    "Serial Number": "F1WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "VOLVO3-D1",
    "IP Address": "10.24.3.137",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "VOLVO-D1",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "23 Oct 2026 [08:33:35]",
    "Last Connected": "23 Oct 2026 [12:14:41]",
    "Last Scanned": "17 Oct 2026 [14:42:04]",
    "MAC Address": "48-4D-7E-9E-B7-1C",
    "Serial Number": "HSTJH92",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STOREU1-D1",
    "IP Address": "10.24.1.70",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STOREU1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:19]",
    "Last Scanned": "31 Oct 2026 [12:12:17]",
    "MAC Address": "9C-67-D6-6B-7A-F6",
    "Serial Number": "F4P0P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "LASERCUTTING4",
    "IP Address": "10.24.1.216",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "LASERCUT4-D1",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [14:12:45]",
    "Last Connected": "13 Nov 2026 [10:03:46]",
    "Last Scanned": "04 Nov 2026 [13:06:07]",
    "MAC Address": "CC-96-E5-1D-98-AE",
    "Serial Number": "FV117X3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "FARO4-L2",
    "IP Address": "10.24.1.231",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "POLYWORKS",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:35]",
    "Last Scanned": "31 Oct 2026 [12:49:05]",
    "MAC Address": "64-79-F0-CA-88-61",
    "Serial Number": "5CD119FZCM",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MKT3-L1",
    "IP Address": "172.32.2.89",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll GDrive",
    "User Name": "MKT3-NB1",
    "Policy": "BlockAll GDrive",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:37:33]",
    "Last Scanned": "31 Oct 2026 [14:58:23]",
    "MAC Address": "08-F9-7E-57-A6-13",
    "Serial Number": "3NMNVF4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTCNC1-D1",
    "IP Address": "10.24.1.174",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MTCNC-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:16]",
    "Last Scanned": "31 Oct 2026 [14:16:41]",
    "MAC Address": "54-BF-64-76-96-FF",
    "Serial Number": "D3YG9R2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTS1-D2",
    "IP Address": "10.24.1.151",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS1-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:25]",
    "Last Scanned": "31 Oct 2026 [12:10:04]",
    "MAC Address": "FC-4C-EA-1A-A3-FF",
    "Serial Number": "JS9HBK4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRD-L1",
    "IP Address": "10.24.1.68",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "HRDU1-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:23]",
    "Last Scanned": "31 Oct 2026 [17:03:48]",
    "MAC Address": "9C-C7-D3-4F-4C-8A",
    "Serial Number": "5CG5343WXG",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRDU1-L2",
    "IP Address": "10.24.1.188",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "HRDU1-L2",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "26 Oct 2026 [13:18:13]",
    "Last Connected": "26 Oct 2026 [17:20:50]",
    "Last Scanned": "01 Aug 2026 [13:11:24]",
    "MAC Address": "A8-E2-91-EE-E1-32",
    "Serial Number": "5CG5140399",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADU1-NB2",
    "IP Address": "10.24.1.227",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QADU1-NB2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:06]",
    "Last Scanned": "17 Oct 2026 [12:30:07]",
    "MAC Address": "E4-A4-71-2E-B0-FD",
    "Serial Number": "J7MXKC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "SOURCING-NB3",
    "IP Address": "192.168.1.100",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG2",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "Administrator",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "24 Oct 2026 [12:34:10]",
    "MAC Address": "34-02-86-B8-47-50",
    "Serial Number": "5CG525402W",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 8.1 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HRD3-D1",
    "IP Address": "10.24.3.122",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "admin",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "05 Nov 2026 [10:49:44]",
    "Last Connected": "11 Nov 2026 [12:58:01]",
    "Last Scanned": "31 Oct 2026 [12:18:45]",
    "MAC Address": "E4-54-E8-CB-16-99",
    "Serial Number": "61MXJ23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "GATE1-D1",
    "IP Address": "10.24.1.154",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "GATE1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [10:02:01]",
    "Last Scanned": "31 Oct 2026 [12:17:46]",
    "MAC Address": "C0-25-A5-AB-9D-DD",
    "Serial Number": "DC70BM3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINTENANCE1-D1",
    "IP Address": "10.24.1.118",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QUALITY1-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:52]",
    "Last Scanned": "31 Oct 2026 [15:12:25]",
    "MAC Address": "7C-05-07-0E-E0-D9",
    "Serial Number": "",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADHEAD-L2",
    "IP Address": "192.168.0.102",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "Q-HEAD-L2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "11 Nov 2026 [08:36:29]",
    "Last Connected": "12 Nov 2026 [11:00:46]",
    "Last Scanned": "31 Oct 2026 [12:26:34]",
    "MAC Address": "14-85-7F-19-4E-11",
    "Serial Number": "5CD124JMFT",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PURCHASE1-D1",
    "IP Address": "10.24.1.145",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PURCHASE1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:02]",
    "Last Scanned": "17 Oct 2026 [12:37:31]",
    "MAC Address": "98-90-96-C9-DA-DB",
    "Serial Number": "J1WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTSU1-D2",
    "IP Address": "10.24.2.26",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "GATE2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [15:06:20]",
    "Last Scanned": "31 Oct 2026 [12:22:10]",
    "MAC Address": "48-4D-7E-A6-80-BA",
    "Serial Number": "18SFXH2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ICQC-D1",
    "IP Address": "10.24.1.143",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ICQAD1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:00]",
    "Last Scanned": "31 Oct 2026 [12:34:38]",
    "MAC Address": "50-9A-4C-08-8F-F5",
    "Serial Number": "6RW7NK2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADM1-D4",
    "IP Address": "10.24.1.152",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QADM1-D4",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:46:23]",
    "Last Scanned": "31 Oct 2026 [12:32:47]",
    "MAC Address": "98-90-96-C9-DA-F3",
    "Serial Number": "62WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PPMCM1-D1",
    "IP Address": "10.24.1.148",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PPMCM1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:04:27]",
    "Last Scanned": "31 Oct 2026 [12:39:21]",
    "MAC Address": "98-90-96-C9-D4-4F",
    "Serial Number": "33WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODU4-D1",
    "IP Address": "10.24.1.214",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PROD4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:03:00]",
    "Last Scanned": "24 Oct 2026 [14:27:07]",
    "MAC Address": "20-88-10-8F-64-46",
    "Serial Number": "76XBS14",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PPMC2-D1",
    "IP Address": "10.24.2.20",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PPMCU2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:16]",
    "Last Scanned": "17 Oct 2026 [12:29:16]",
    "MAC Address": "8C-EC-4B-AA-4A-9A",
    "Serial Number": "DQ507T2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTSU1-L2",
    "IP Address": "10.24.1.76",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS1-L2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:49]",
    "Last Scanned": "31 Oct 2026 [14:25:33]",
    "MAC Address": "08-F9-7E-57-AC-AF",
    "Serial Number": "5YLNVF4",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL-D2",
    "IP Address": "192.168.1.37",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MPIPL",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MPIPL D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "07 Nov 2026 [11:02:25]",
    "Last Connected": "12 Nov 2026 [09:55:46]",
    "Last Scanned": "07 Nov 2026 [12:14:09]",
    "MAC Address": "20-88-10-8D-5B-41",
    "Serial Number": "JSSBS14",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CEOCORP-L1",
    "IP Address": "192.168.101.11",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "CORP-CEO",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [08:47:35]",
    "Last Connected": "13 Nov 2026 [07:40:46]",
    "Last Scanned": "19 Oct 2026 [11:31:11]",
    "MAC Address": "F8-FE-5E-D2-87-2D",
    "Serial Number": "5CD411JN55",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-TIME",
    "IP Address": "10.24.1.27",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:01:59]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-00",
    "Serial Number": "4449-3444-3445-6523-3458-0070-92",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "FARO",
    "IP Address": "10.24.1.222",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "admin",
    "Policy": "BlockAll",
    "Policy Status": "Published",
    "Virus DB Date (GMT+5:30)": "20 Oct 2026 [09:54:01]",
    "Last Connected": "20 Oct 2026 [13:23:24]",
    "Last Scanned": "17 Oct 2026 [13:18:47]",
    "MAC Address": "90-65-84-D3-24-C6",
    "Serial Number": "5CG3440K72",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-MT-RDP",
    "IP Address": "10.24.1.11",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->RDP Server",
    "User Name": "Administrator",
    "Policy": "RDP Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:04]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-BB-67-0C",
    "Serial Number": "0699-7101-1115-0567-6877-8057-25",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U1MFGHEAD-L1",
    "IP Address": "10.24.1.184",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "U1MFGHEAD-L1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:03:43]",
    "Last Scanned": "-",
    "MAC Address": "F8-FE-5E-D6-2E-23",
    "Serial Number": "5CD411JN3Q",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DDP1-D2",
    "IP Address": "10.24.3.134",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "DDP3-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:01]",
    "Last Scanned": "07 Nov 2026 [12:45:35]",
    "MAC Address": "F4-8E-38-82-AB-A8",
    "Serial Number": "GTYZXC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U1QADHEAD-L3",
    "IP Address": "172.30.1.85",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "U1QADHEAD-L3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:55:45]",
    "Last Scanned": "31 Oct 2026 [13:52:28]",
    "MAC Address": "F8-FE-5E-D6-2D-8D",
    "Serial Number": "5CD411JN48",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINTENANCE2-D1",
    "IP Address": "10.24.2.43",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "admin",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "04 Nov 2026 [14:19:58]",
    "Last Connected": "05 Nov 2026 [08:55:52]",
    "Last Scanned": "24 Oct 2026 [12:59:39]",
    "MAC Address": "00-E0-4C-CD-4F-A4",
    "Serial Number": "To be filled by O.E.M.",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINTM1-D1",
    "IP Address": "10.24.1.160",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MAINTM1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:02]",
    "Last Scanned": "17 Oct 2026 [12:22:47]",
    "MAC Address": "10-FF-E0-FD-88-6E",
    "Serial Number": "Default string",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DESKTOP-8PESFRD",
    "IP Address": "192.168.1.15",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "Admin",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:45:46]",
    "Last Scanned": "13 Nov 2026 [00:09:20]",
    "MAC Address": "40-B0-34-F5-0C-74",
    "Serial Number": "SGH824PXB1",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADU4-D1",
    "IP Address": "10.24.1.215",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QAD4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:50]",
    "Last Scanned": "31 Oct 2026 [12:33:18]",
    "MAC Address": "20-88-10-8A-36-7D",
    "Serial Number": "33M9S14",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PEDCORP-D1",
    "IP Address": "10.24.3.190",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PEDCORP-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:03]",
    "Last Scanned": "07 Nov 2026 [12:28:31]",
    "MAC Address": "64-00-6A-14-BD-71",
    "Serial Number": "3J4J882",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MARKETINGU1-L1",
    "IP Address": "10.24.1.220",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PURCHASE4-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [18:08:06]",
    "Last Scanned": "31 Oct 2026 [12:34:40]",
    "MAC Address": "E4-A4-71-2E-B0-A3",
    "Serial Number": "3YL5LC2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MAINT3-D1",
    "IP Address": "10.24.3.96",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MAINT3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:55]",
    "Last Scanned": "01 Nov 2026 [00:59:57]",
    "MAC Address": "8C-EC-4B-60-4A-F2",
    "Serial Number": "1WXGGP2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTS2-D1",
    "IP Address": "10.24.1.144",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:03]",
    "Last Scanned": "31 Oct 2026 [12:41:15]",
    "MAC Address": "50-9A-4C-38-D5-E7",
    "Serial Number": "8F7KZL2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MACHINESHOP3-D1",
    "IP Address": "10.24.3.55",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MACHINESHOP3-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:03]",
    "Last Scanned": "31 Oct 2026 [12:26:29]",
    "MAC Address": "E4-54-E8-CD-9A-89",
    "Serial Number": "HBTRT23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "DDP1-D1",
    "IP Address": "10.24.1.158",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "DDP-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [17:32:12]",
    "Last Scanned": "31 Oct 2026 [12:46:39]",
    "MAC Address": "64-00-6A-62-05-4A",
    "Serial Number": "F1K1N62",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U4QADHEAD-L1",
    "IP Address": "10.24.1.53",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "U4QADHEAD-L1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:02]",
    "Last Scanned": "01 Nov 2026 [09:33:21]",
    "MAC Address": "F8-FE-5E-D6-2D-7E",
    "Serial Number": "5CD411JN3S",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QUALITY-D1",
    "IP Address": "10.24.1.141",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QUALITY-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:50]",
    "Last Scanned": "31 Oct 2026 [12:37:19]",
    "MAC Address": "98-90-96-C9-DB-B1",
    "Serial Number": "11WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ACCOUNTSU1-D1",
    "IP Address": "10.24.1.72",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "ACCOUNTS1-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:43]",
    "Last Scanned": "31 Oct 2026 [12:13:07]",
    "MAC Address": "9C-B1-50-44-90-35",
    "Serial Number": "CSY1P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORE4-D1",
    "IP Address": "10.24.1.153",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORES4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:23]",
    "Last Scanned": "31 Oct 2026 [12:19:43]",
    "MAC Address": "20-88-10-6F-0A-0B",
    "Serial Number": "78YDWY3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "COMMON3-D1",
    "IP Address": "10.24.1.213",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "GATE4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:03:16]",
    "Last Scanned": "31 Oct 2026 [12:37:17]",
    "MAC Address": "98-90-96-C9-DB-51",
    "Serial Number": "80WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCT1-QA",
    "IP Address": "10.24.1.181",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "U1PRODUCT-QA",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:01]",
    "Last Scanned": "31 Oct 2026 [13:11:53]",
    "MAC Address": "28-D0-43-E8-E3-BA",
    "Serial Number": "5CG4350C4X",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTGSAPSRVR",
    "IP Address": "10.24.1.30",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:18]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-05",
    "Serial Number": "3527-8724-7566-7217-4907-0524-32",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CORPMKT-L3",
    "IP Address": "10.24.3.133",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CORPMKT-L3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:01:55]",
    "Last Scanned": "31 Oct 2026 [12:37:51]",
    "MAC Address": "B0-C0-90-C6-78-28",
    "Serial Number": "3G695C2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADM1-D3",
    "IP Address": "10.24.1.183",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QADM1-D3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [18:55:20]",
    "Last Scanned": "31 Oct 2026 [12:13:43]",
    "MAC Address": "98-90-96-C9-DC-AD",
    "Serial Number": "2WVR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QUALITY2-D1",
    "IP Address": "10.24.2.19",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "QUALITYU2-D1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:16]",
    "Last Scanned": "26 Aug 2026 [00:42:00]",
    "MAC Address": "E4-54-E8-C8-FF-3E",
    "Serial Number": "22XMB23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL-D1",
    "IP Address": "192.168.1.33",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "MPIPL-D1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "13 Nov 2026 [00:16:49]",
    "MAC Address": "D0-46-0C-91-30-28",
    "Serial Number": "C1XXM24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CORPHRD-L3",
    "IP Address": "172.32.2.48",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "CORPHR-L3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "12 Nov 2026 [18:31:12]",
    "Last Scanned": "31 Oct 2026 [14:48:47]",
    "MAC Address": "F8-FE-5E-D4-B8-D6",
    "Serial Number": "5CD411JN3Z",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION4-D2",
    "IP Address": "10.24.1.149",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PRODUCTION4-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:59]",
    "Last Scanned": "17 Oct 2026 [12:32:26]",
    "MAC Address": "8C-EC-4B-C7-AC-9B",
    "Serial Number": "92WS3W2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CCTV",
    "IP Address": "192.168.0.4",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "Admin",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "07 Nov 2026 [12:21:39]",
    "MAC Address": "F4-8E-38-80-9B-05",
    "Serial Number": "BYX6B22",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-PAY",
    "IP Address": "10.24.1.29",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:01:55]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-02",
    "Serial Number": "7781-0753-7632-6411-2321-7826-70",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL-D3",
    "IP Address": "192.168.1.46",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MPIPL",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "MPIPL D3",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:50:46]",
    "Last Scanned": "07 Nov 2026 [12:17:49]",
    "MAC Address": "20-88-10-8F-9A-07",
    "Serial Number": "2PSBS14",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MPIPL1-L2",
    "IP Address": "192.168.1.39",
    "Endpoint Status": "Roaming",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "MPIPL-L2",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:00:49]",
    "Last Scanned": "24 Oct 2026 [17:12:13]",
    "MAC Address": "E4-0D-36-12-70-14",
    "Serial Number": "5CD337GTYS",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PURCHASE3-D1",
    "IP Address": "10.24.3.44",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Default",
    "User Name": "VOLVO-D1",
    "Policy": "Default_EPP",
    "Policy Status": "Not Published",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [15:16:38]",
    "Last Scanned": "01 Aug 2026 [12:29:09]",
    "MAC Address": "E4-54-E8-CB-13-DA",
    "Serial Number": "CYLXJ23",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 10 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QADM1-D2",
    "IP Address": "10.24.1.169",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QADM1-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:58]",
    "Last Scanned": "31 Oct 2026 [12:13:46]",
    "MAC Address": "98-90-96-C9-D6-42",
    "Serial Number": "G1WR542",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U1ENGINEERING-L1",
    "IP Address": "10.24.1.186",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "COPED-L1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [09:23:46]",
    "Last Scanned": "24 Oct 2026 [12:43:04]",
    "MAC Address": "28-D0-43-E8-E6-3A",
    "Serial Number": "5CG4350D0C",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTCNCSAPLIVE",
    "IP Address": "10.24.1.12",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:05]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-BB-67-09",
    "Serial Number": "6302-7693-2157-8002-3280-4087-86",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "STORES2-D1",
    "IP Address": "10.24.2.37",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "STORESU2-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:34]",
    "Last Scanned": "31 Oct 2026 [12:26:01]",
    "MAC Address": "8C-EC-4B-AA-4A-DB",
    "Serial Number": "DQ3R6T2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "QAD4-D2",
    "IP Address": "10.24.1.178",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "QAD4-D2",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:14]",
    "Last Scanned": "31 Oct 2026 [12:19:41]",
    "MAC Address": "20-88-10-AD-55-CD",
    "Serial Number": "GQJ9M24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "AI-SYSTEM",
    "IP Address": "10.24.1.156",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "AISAP",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:21]",
    "Last Scanned": "13 Nov 2026 [00:43:01]",
    "MAC Address": "00-BE-43-8E-82-96",
    "Serial Number": "53C7SN3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "HOME-MG",
    "IP Address": "192.168.1.132",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "WORKGROUP",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "Admin",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [08:50:46]",
    "Last Scanned": "31 Oct 2026 [08:52:06]",
    "MAC Address": "08-8E-90-A0-09-6A",
    "Serial Number": "HHW7JK2",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-VM-Veeam",
    "IP Address": "10.24.1.26",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:02:00]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-28-97-06",
    "Serial Number": "2485-7875-8344-6686-2087-2501-69",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2022 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "MTG-MT-RDP1",
    "IP Address": "10.24.1.105",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->RDP Server",
    "User Name": "Administrator",
    "Policy": "RDP Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:25]",
    "Last Scanned": "-",
    "MAC Address": "00-15-5D-BB-67-05",
    "Serial Number": "0699-7101-1115-0567-6877-8057-25",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "ITSSRVR",
    "IP Address": "10.24.1.9",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:38]",
    "Last Scanned": "-",
    "MAC Address": "00-0C-29-1D-CF-38",
    "Serial Number": "VMware-56 4d 6a 7d cd 09 38 67-00 8d 18 df 5b 1d cf 38",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PPMC4-D1",
    "IP Address": "172.32.2.119",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll",
    "User Name": "PPMC4-D1",
    "Policy": "BlockAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:03:07]",
    "Last Scanned": "31 Oct 2026 [12:13:37]",
    "MAC Address": "E8-CF-83-2F-B3-A1",
    "Serial Number": "GCX1P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "IT-Support",
    "IP Address": "10.24.1.98",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Windows Server",
    "User Name": "Administrator",
    "Policy": "Windows Server",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:22]",
    "Last Scanned": "-",
    "MAC Address": "CC-96-E5-38-FD-F1",
    "Serial Number": "9GHWMZ3",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows Server 2016 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "U3MFGHEAD-L1",
    "IP Address": "10.24.3.129",
    "Endpoint Status": "Offline",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->BlockAll_WhatsApp",
    "User Name": "MFGHEADU3-L1",
    "Policy": "BlockAll_WhatsApp",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "12 Nov 2026 [17:37:56]",
    "Last Scanned": "01 Oct 2026 [09:58:51]",
    "MAC Address": "9C-C7-D3-52-D4-00",
    "Serial Number": "5CG5343V7B",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "PRODUCTION1-D2",
    "IP Address": "10.24.1.74",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->UnBlockUSB",
    "User Name": "PRODUCTION1-D2",
    "Policy": "UnBlockUSB",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "13 Nov 2026 [00:05:42]",
    "Last Connected": "13 Nov 2026 [10:04:43]",
    "Last Scanned": "11 Nov 2026 [12:15:41]",
    "MAC Address": "9C-67-D6-54-3A-B2",
    "Serial Number": "6X22P24",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "AUDIT1-L1",
    "IP Address": "10.24.1.37",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->Default",
    "User Name": "AUDIT-L1",
    "Policy": "Default_EPP",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [15:43:13]",
    "Last Connected": "13 Nov 2026 [10:02:21]",
    "Last Scanned": "-",
    "MAC Address": "48-E2-44-2D-F2-AB",
    "Serial Number": "CND5464N6B",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": ""
  },
  {
    "User Id": "",
    "Name": "",
    "Endpoint Name": "CORP-ITHEAD-L1",
    "IP Address": "10.24.1.31",
    "Endpoint Status": "Online",
    "Roaming Service": "false",
    "Domain Name": "MTG",
    "Group Name": "Micro-Tech Group->OpenAll",
    "User Name": "CORPITHEAD-L1",
    "Policy": "OpenAll",
    "Policy Status": "Applied",
    "Virus DB Date (GMT+5:30)": "12 Nov 2026 [11:08:15]",
    "Last Connected": "13 Nov 2026 [10:03:29]",
    "Last Scanned": "15 Oct 2026 [01:56:19]",
    "MAC Address": "D0-65-78-F2-AA-BC",
    "Serial Number": "5CD4297N1N",
    "Client Version": "10.14.0.0",
    "Operating System": "Windows 11 64 bit",
    "DLP": "No",
    "AV Status": "Success",
    "EDR Sensor Version": "\""
  }
];

const STATIC_DOCUMENTS = [
  { id: 1, doc_number: 'SOP-PRD-004', title: 'Machine start-up and shutdown', category: 'SOP', revision: 'C', updated_date: '2026-09-12', file_location: String.raw`\\fileserver\Production\SOP\SOP-PRD-004.pdf` },
  { id: 2, doc_number: 'SOP-PRD-011', title: 'First-off inspection and release', category: 'SOP', revision: 'B', updated_date: '2026-07-03', file_location: String.raw`\\fileserver\Production\SOP\SOP-PRD-011.pdf` },
  { id: 3, doc_number: 'SOP-MNT-002', title: 'Preventive maintenance schedule for VMC and turning centres', category: 'SOP', revision: 'D', updated_date: '2026-10-02', file_location: String.raw`\\fileserver\Maintenance\SOP\SOP-MNT-002.pdf` },
  { id: 4, doc_number: 'QP-QA-001', title: 'Control of non-conforming product', category: 'Quality', revision: 'E', updated_date: '2026-08-21', file_location: String.raw`\\fileserver\Quality\QMS\QP-QA-001.pdf` },
  { id: 5, doc_number: 'QP-QA-007', title: 'Calibration of measuring instruments', category: 'Quality', revision: 'C', updated_date: '2026-10-28', file_location: String.raw`\\fileserver\Quality\QMS\QP-QA-007.pdf` },
  { id: 6, doc_number: 'POL-HR-001', title: 'Leave and attendance policy', category: 'HR', revision: 'F', updated_date: '2026-04-01', file_location: String.raw`\\fileserver\HR\Policies\POL-HR-001.pdf` },
  { id: 7, doc_number: 'POL-HR-006', title: 'Code of conduct', category: 'HR', revision: 'B', updated_date: '2026-01-15', file_location: String.raw`\\fileserver\HR\Policies\POL-HR-006.pdf` },
  { id: 8, doc_number: 'POL-EHS-001', title: 'Safety policy and PPE requirements', category: 'Safety', revision: 'G', updated_date: '2026-11-02', file_location: String.raw`\\fileserver\EHS\Policies\POL-EHS-001.pdf` },
  { id: 9, doc_number: 'EHS-FRM-014', title: 'Near-miss report form', category: 'Safety', revision: 'B', updated_date: '2026-05-18', file_location: String.raw`\\fileserver\EHS\Forms\EHS-FRM-014.pdf` },
  { id: 10, doc_number: 'FRM-STR-003', title: 'Tool issue and return slip', category: 'Forms', revision: 'A', updated_date: '2026-10-30', file_location: String.raw`\\fileserver\Stores\Forms\FRM-STR-003.pdf` },
  { id: 11, doc_number: 'FRM-HR-012', title: 'Leave application form', category: 'Forms', revision: 'C', updated_date: '2026-04-01', file_location: String.raw`\\fileserver\HR\Forms\FRM-HR-012.pdf` },
  { id: 12, doc_number: 'IT-GOV-001', title: 'Information Security and IT Governance Manual', category: 'IT Policy', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\Policies\IT-GOV-001.pdf` },
  { id: 13, doc_number: 'IT-SOP-001', title: 'Backup and restore', category: 'IT SOP', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\SOP\IT-SOP-001.pdf` },
  { id: 14, doc_number: 'IT-SOP-002', title: 'User account creation and exit', category: 'IT SOP', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\SOP\IT-SOP-002.pdf` },
  { id: 15, doc_number: 'IT-SOP-003', title: 'Microsoft 365 administration', category: 'IT SOP', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\SOP\IT-SOP-003.pdf` },
  { id: 16, doc_number: 'IT-SOP-004', title: 'SAP B1 administration', category: 'IT SOP', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\SOP\IT-SOP-004.pdf` },
  { id: 17, doc_number: 'IT-SOP-005', title: 'Disaster recovery', category: 'IT SOP', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\SOP\IT-SOP-005.pdf` },
  { id: 18, doc_number: 'IT-FRM-001', title: 'User account request', category: 'IT Form', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\Forms\IT-FRM-001.pdf` },
  { id: 19, doc_number: 'IT-FRM-002', title: 'Access change and exit checklist', category: 'IT Form', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\Forms\IT-FRM-002.pdf` },
  { id: 20, doc_number: 'IT-FRM-003', title: 'Change request', category: 'IT Form', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\Forms\IT-FRM-003.pdf` },
  { id: 21, doc_number: 'IT-FRM-004', title: 'Incident report', category: 'IT Form', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\Forms\IT-FRM-004.pdf` },
  { id: 22, doc_number: 'IT-FRM-005', title: 'Asset issue and return', category: 'IT Form', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\Forms\IT-FRM-005.pdf` },
  { id: 23, doc_number: 'IT-FRM-006', title: 'Vendor assessment', category: 'IT Form', revision: 'Draft', updated_date: '2026-11-10', file_location: String.raw`\\fileserver\IT\Forms\IT-FRM-006.pdf` }
];

function makeRateLimiter(maxRequests, windowMs) {
  const buckets = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.socket.remoteAddress || 'unknown';
    let bucket = buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    if (buckets.size > 5000) {
      for (const [ip, value] of buckets) if (now >= value.resetAt) buckets.delete(ip);
      if (buckets.size > 5000) buckets.clear();
    }
    if (bucket.count >= maxRequests) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
      return res.status(429).json({ success: false, message: 'Too many attempts. Please try again later.' });
    }
    bucket.count += 1;
    next();
  };
}
const validText = (value, maxLength, allowEmpty = false) =>
  typeof value === 'string' && value.length <= maxLength && (allowEmpty || value.trim().length > 0);
const validEmail = (value, maxLength = 120) =>
  typeof value === 'string' && value.length <= maxLength && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const validIsoDate = (value) =>
  typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
  !Number.isNaN(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
const validHttpUrl = (value) => {
  if (!validText(value, 255)) return false;
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
  } catch {
    return false;
  }
};
const validRowId = (req, res, next, id) => {
  if (!/^[1-9]\d{0,9}$/.test(id)) return res.status(400).json({ success: false, message: 'Invalid record ID.' });
  next();
};
const nextId = (rows) => rows.reduce((max, item) => Math.max(max, Number(item.id) || 0), 0) + 1;

module.exports = function createApiRouter({ jwtSecret }) {
  const JWT_SECRET = jwtSecret;
  const verifyToken = async (req, res, next) => {
    const header = req.headers.authorization;
    const cookie = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith('mt_session='));
    const cookieToken = cookie ? cookie.slice('mt_session='.length) : '';
    const parts = header ? header.split(' ') : [];
    const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : cookieToken;
    if (!token) return res.status(401).json({ success: false, message: 'Authentication required.' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const account = decoded.auth_source === 'static' ? staticAccountById.get(decoded.id) : null;
      if (!account || account.status !== 'active' || decoded.role !== account.role) return res.status(403).json({ success: false, message: 'Account is inactive or unavailable.' });
      req.user = { ...decoded, role: account.role, status: account.status };
      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') return res.status(401).json({ success: false, expired: true, message: 'Session expired. Please log in again.' });
      return res.status(401).json({ success: false, message: 'Session expired or invalid. Please log in again.' });
    }
  };
  const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Access denied. Administrator privileges required.' });
    next();
  };
  const loginLimiter = makeRateLimiter(10, 15 * 60 * 1000);
  const recoveryLimiter = makeRateLimiter(5, 15 * 60 * 1000);
  const otpDigest = (userId, otp) => crypto.createHmac('sha256', JWT_SECRET).update(`${userId}:${otp}`).digest('hex').slice(0, 10);
  const escapeHtml = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const sessionCookie = (token, persistent = false) => {
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    const age = persistent ? '; Max-Age=604800' : '';
    return `mt_session=${token}; Path=/; HttpOnly; SameSite=Strict${secure}${age}`;
  };
  const api = express.Router();
  api.use((req, res, next) => {
    if (['POST', 'PUT', 'PATCH'].includes(req.method) &&
        req.path !== '/auth/logout' &&
        (!req.is('application/json') || !req.body || typeof req.body !== 'object' || Array.isArray(req.body))) {
      return res.status(415).json({ success: false, message: 'A JSON object request body is required.' });
    }
    next();
  });
  const authRouter = (() => {
    const router = express.Router();

    // POST /api/auth/login
    router.post('/login', loginLimiter, async (req, res) => {
      try {
        const rawEmpId = req.body.employee_id || req.body.emp_id || req.body.username;
        const { password } = req.body;

        if (!rawEmpId) {
          return res.status(400).json({ success: false, message: 'User ID is required.' });
        }

        if (typeof rawEmpId !== 'string' || rawEmpId.trim().length > 120) {
          return res.status(400).json({ success: false, message: 'Enter a valid User ID.' });
        }
        const loginId = rawEmpId.trim();

        if (typeof password !== 'string' || password.length < 1 || Buffer.byteLength(password, 'utf8') > 72) {
          return res.status(400).json({ success: false, message: 'Password is required.' });
        }

        const staticUser = STATIC_ACCOUNTS.find((account) =>
          account.emp_id === loginId || account.username.toLowerCase() === loginId.toLowerCase()
        );
        if (!staticUser) return res.status(401).json({ success: false, message: 'Invalid Employee ID or password.' });
        const user = staticUser;

        // Check account status before verifying password
        if (user.status !== 'active' || user.is_active === 0 || user.is_active === false) {
          return res.status(403).json({
            success: false,
            message: 'Account is inactive. Please contact HR or plant administration.'
          });
        }

        // Verify password with bcrypt
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
          return res.status(401).json({ success: false, message: 'Invalid Employee ID or password.' });
        }

        const tokenPayload = {
          id: user.id,
          emp_id: user.emp_id,
          username: user.username,
          email: user.email,
          full_name: user.full_name,
          role: user.role,
          status: user.status || 'active',
          phone_ext: user.phone_ext,
          department: user.department,
          shift: user.shift,
          auth_source: 'static'
        };

        const remember = req.body.remember_me === true;
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: remember ? '7d' : '8h' });
        res.setHeader('Set-Cookie', sessionCookie(token, remember));
        res.setHeader('Cache-Control', 'no-store');

        const responseUser = { ...tokenPayload };
        delete responseUser.auth_source;
        res.json({
          success: true,
          message: 'Login successful',
          user: responseUser
        });
      } catch (err) {
        console.error('Login request failed.');
        res.status(500).json({ success: false, message: 'Internal server error during login.' });
      }
    });

    router.post('/logout', (req, res) => {
      const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
      res.setHeader('Set-Cookie', `mt_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, message: 'Logged out.' });
    });

    // GET /api/auth/me
    router.get('/me', verifyToken, async (req, res) => {
      try {
        const account = staticAccountById.get(req.user.id);
        if (!account) return res.status(404).json({ success: false, message: 'User not found.' });
        res.json({ success: true, user: { id: account.id, username: account.username, emp_id: account.emp_id, email: '', full_name: account.full_name, role: account.role, status: account.status, phone_ext: '', department: '', shift: '', created_at: null } });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch user profile.' });
      }
    });

    // POST /api/auth/forgot-password
    router.post('/forgot-password', recoveryLimiter, (req, res) => {
      const { identifier } = req.body;
      if (typeof identifier !== 'string' || !identifier.trim() || identifier.trim().length > 254) {
        return res.status(400).json({ success: false, message: 'Employee ID or registered Email is required.' });
      }
      return res.status(503).json({ success: false, message: 'Password recovery is not configured for code-managed accounts. Contact the administrator to update the server-side bcrypt hash.' });
    });

    // POST /api/auth/reset-password
    router.post('/reset-password', recoveryLimiter, (req, res) => {
      const { identifier, otp, newPassword } = req.body;
      if (typeof identifier !== 'string' || !identifier.trim() || identifier.trim().length > 254 ||
          typeof otp !== 'string' || !/^\d{6}$/.test(otp) || typeof newPassword !== 'string') {
        return res.status(400).json({ success: false, message: 'Employee ID/Email, OTP, and new password are required.' });
      }
      if (newPassword.length < 8 || Buffer.byteLength(newPassword, 'utf8') > 72) {
        return res.status(400).json({ success: false, message: 'Password must be 8 to 72 bytes long.' });
      }
      return res.status(503).json({ success: false, message: 'Password reset is not configured for code-managed accounts. Contact the administrator to update the server-side bcrypt hash.' });
    });


    return router;
  })();
  api.use('/auth', authRouter);

  const boardRouter = (() => {
    const router = express.Router();

    // GET /api/board
    router.get('/', async (req, res) => {
      res.json({ success: true, data: { board: MEMORY.board, shifts: [], emergency: [] } });
    });

    // PUT /api/board (Admin only)
    router.put('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const {
          last_incident_date,
          incident_free_target,
          on_time_delivery,
          delivery_note,
          machines_down,
          machines_note
        } = req.body;

        const target = Number(incident_free_target);
        if (!validIsoDate(last_incident_date) ||
            !Number.isInteger(target) || target < 1 || target > 3650 ||
            (on_time_delivery != null && (typeof on_time_delivery !== 'string' || !/^\d{1,3}(?:\.\d{1,2})?%$/.test(on_time_delivery) || Number(on_time_delivery.slice(0, -1)) > 100)) ||
            !validText(delivery_note == null ? '' : delivery_note, 100, true) ||
            !validText(machines_down == null ? '' : machines_down, 20, true) ||
            !validText(machines_note == null ? '' : machines_note, 120, true)) {
          return res.status(400).json({ success: false, message: 'Invalid shop floor board values.' });
        }

        const updatedBoard = MEMORY.board = {
          last_incident_date,
          incident_free_target: target,
          on_time_delivery: on_time_delivery || 'Not configured',
          delivery_note: delivery_note || '',
          machines_down: machines_down || 'Not configured',
          machines_note: machines_note || ''
        };

        // Emit Socket.IO real-time update
        if (req.app.get('io')) {
          req.app.get('io').emit('board:updated', updatedBoard);
        }

        res.json({ success: true, message: 'Shop floor figures updated for this server run.', data: updatedBoard });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update shop floor board figures.' });
      }
    });


    return router;
  })();
  api.use('/board', boardRouter);

  const announcementsRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/announcements
    router.get('/', verifyToken, async (req, res) => {
      try {
        const rows = MEMORY.announcements.slice().sort((a, b) => Number(b.is_pinned) - Number(a.is_pinned) || String(b.posted_date).localeCompare(String(a.posted_date)) || b.id - a.id);
        res.json({ success: true, data: rows });
      } catch (err) { res.status(500).json({ success: false, message: 'Failed to retrieve announcements.' }); }
    });

    // POST /api/announcements (Admin only)
    router.post('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { category, headline, body, is_pinned } = req.body;
        const categories = ['Safety', 'Production', 'Maintenance', 'Quality', 'HR', 'General'];
        if (!validText(headline, 160) || (body != null && !validText(body, 10000, true)) ||
            (category != null && !categories.includes(category)) ||
            (is_pinned != null && ![true, false, 0, 1].includes(is_pinned))) {
          return res.status(400).json({ success: false, message: 'Invalid announcement details.' });
        }

        const posted_date = new Date().toISOString().slice(0, 10);
        const cat = category || 'General';
        const pinned = is_pinned ? 1 : 0;
        const bodyText = (body || '').trim();

        const newAnnouncement = {
          id: nextId(MEMORY.announcements),
          category: cat,
          headline: headline.trim(),
          body: bodyText,
          is_pinned: pinned,
          posted_date,
          created_by: req.user.id
        };
        MEMORY.announcements.push(newAnnouncement);

        // Emit Socket.IO
        if (req.app.get('io')) {
          req.app.get('io').emit('announcement:created', newAnnouncement);
        }

        res.status(201).json({ success: true, message: 'Announcement posted successfully.', data: newAnnouncement });
      } catch (err) {
        console.error('Post announcement error:', err);
        res.status(500).json({ success: false, message: 'Failed to post announcement.' });
      }
    });

    // PATCH /api/announcements/:id/pin (Admin only)
    router.patch('/:id/pin', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { is_pinned } = req.body;
        if (![true, false, 0, 1].includes(is_pinned)) {
          return res.status(400).json({ success: false, message: 'Invalid pin value.' });
        }

        const announcement = MEMORY.announcements.find((item) => String(item.id) === String(id));
        if (!announcement) return res.status(404).json({ success: false, message: 'Announcement not found.' });
        announcement.is_pinned = is_pinned ? 1 : 0;

        if (req.app.get('io')) {
          req.app.get('io').emit('announcement:pinned', { id, is_pinned: is_pinned ? 1 : 0 });
        }

        res.json({ success: true, message: 'Announcement pin status updated.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update announcement.' });
      }
    });

    // DELETE /api/announcements/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.announcements.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Announcement not found.' });
        MEMORY.announcements.splice(index, 1);

        // Emit Socket.IO
        if (req.app.get('io')) {
          req.app.get('io').emit('announcement:deleted', { id });
        }

        res.json({ success: true, message: 'Announcement deleted successfully.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete announcement.' });
      }
    });


    return router;
  })();
  api.use('/announcements', announcementsRouter);

  const eventsRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/events
    router.get('/', verifyToken, async (req, res) => {
      res.json({ success: true, data: MEMORY.events.slice().sort((a, b) => String(a.event_date).localeCompare(String(b.event_date)) || a.id - b.id) });
    });

    // POST /api/events (Admin only)
    router.post('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { event_date, title, place_and_time } = req.body;
        if (!validIsoDate(event_date) || !validText(title, 120) ||
            (place_and_time != null && !validText(place_and_time, 120, true))) {
          return res.status(400).json({ success: false, message: 'Invalid event details.' });
        }

        const newEvent = {
          id: nextId(MEMORY.events),
          event_date,
          title: title.trim(),
          place_and_time: (place_and_time || '').trim(),
          created_by: req.user.id
        };
        MEMORY.events.push(newEvent);

        if (req.app.get('io')) {
          req.app.get('io').emit('event:created', newEvent);
        }

        res.status(201).json({ success: true, message: 'Event added for this server run.', data: newEvent });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to add event.' });
      }
    });

    // DELETE /api/events/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.events.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Event not found.' });
        MEMORY.events.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('event:deleted', { id });
        }

        res.json({ success: true, message: 'Event deleted successfully.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete event.' });
      }
    });


    return router;
  })();
  api.use('/events', eventsRouter);

  const employeesRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/employees
    router.get('/', verifyToken, async (req, res) => {
      try {
        const { search, department, shift } = req.query;
        if ((search != null && (typeof search !== 'string' || search.length > 120)) ||
            (department != null && (typeof department !== 'string' || department.length > 80)) ||
            (shift != null && (typeof shift !== 'string' || shift.length > 30))) {
          return res.status(400).json({ success: false, message: 'Invalid employee search filters.' });
        }
        let employees = STATIC_EMPLOYEES.slice().sort((a, b) => a.name.localeCompare(b.name));
        const departments = Array.from(new Map(employees.map((employee) => employee.department.trim()).filter(Boolean).map((name) => [name.toLowerCase(), name])).values()).sort((a, b) => a.localeCompare(b));

        if (search && search.trim()) {
          const q = search.trim().toLowerCase();
          employees = employees.filter(e =>
            (e.name || '').toLowerCase().includes(q) ||
            (e.designation || '').toLowerCase().includes(q) ||
            (e.emp_id || '').toLowerCase().includes(q) ||
            (e.phone_ext || '').includes(q) ||
            (e.email || '').toLowerCase().includes(q)
          );
        }

        if (department && department !== 'All') {
          employees = employees.filter(e => (e.department || '').trim().toLowerCase() === department.trim().toLowerCase());
        }

        if (shift && shift !== 'All') {
          employees = employees.filter(e => e.shift === shift);
        }

        res.json({
          success: true,
          data: employees,
          departments
        });
      } catch (err) {
        console.error('Fetch employees error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve employee directory.' });
      }
    });

    // GET /api/employees/departments
    router.get('/departments', verifyToken, async (req, res) => {
      try {
        const depts = Array.from(new Map(STATIC_EMPLOYEES.map((employee) => employee.department.trim()).filter(Boolean).map((name) => [name.toLowerCase(), name])).values()).sort((a, b) => a.localeCompare(b)).map((name) => ({ name }));
        res.json({ success: true, data: depts });
      } catch (err) { res.status(500).json({ success: false, message: 'Failed to fetch departments.' }); }
    });

    // POST /api/employees (Admin only)
    router.post('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { emp_id, name, designation, department, phone_ext, shift, email } = req.body;
        const validShifts = ['General', 'Shift A', 'Shift B', 'Shift C'];
        if (!validText(emp_id, 120) ||
            !validText(name, 120) || !validText(designation, 100) ||
            !validText(department, 80) || !validText(phone_ext, 20) ||
            (shift != null && !validShifts.includes(shift)) ||
            (email != null && email !== '' && !validEmail(email))) {
          return res.status(400).json({ success: false, message: 'Invalid employee ID or employee details.' });
        }

        if (STATIC_EMPLOYEES.some((employee) => employee.emp_id === emp_id.trim())) {
          return res.status(400).json({ success: false, message: 'An employee with this Employee ID already exists.' });
        }
        const newEmp = {
          id: Math.max(0, ...STATIC_EMPLOYEES.map((employee) => Number(employee.id) || 0)) + 1,
          emp_id: emp_id.trim(),
          name: name.trim(),
          designation: designation.trim(),
          department: department.trim(),
          phone_ext: phone_ext.trim(),
          shift: shift || 'General',
          email: (email || '').trim()
        };
        STATIC_EMPLOYEES.push(newEmp);

        if (req.app.get('io')) {
          req.app.get('io').emit('employee:changed', { action: 'created', employee: newEmp });
        }

        res.status(201).json({ success: true, message: 'Added in memory for this server run; update the code data to keep it after restart.', data: newEmp });
      } catch (err) {
        console.error('Add employee error:', err);
        res.status(500).json({ success: false, message: 'Failed to add employee record.' });
      }
    });

    // PUT /api/employees/:id (Admin only)
    router.put('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { name, designation, department, phone_ext, shift, email } = req.body;

        const validShifts = ['General', 'Shift A', 'Shift B', 'Shift C'];
        if (!validText(name, 120) || !validText(designation, 100) ||
            !validText(department, 80) || !validText(phone_ext, 20) ||
            (shift != null && !validShifts.includes(shift)) ||
            (email != null && email !== '' && !validEmail(email))) {
          return res.status(400).json({ success: false, message: 'Invalid employee details.' });
        }

        const emp = STATIC_EMPLOYEES.find((employee) => String(employee.id) === String(id));
        if (!emp) return res.status(404).json({ success: false, message: 'Employee not found.' });
        Object.assign(emp, { name: name.trim(), designation: designation.trim(), department: department.trim(), phone_ext: phone_ext.trim(), shift: shift || 'General', email: (email || '').trim() });

        if (req.app.get('io')) {
          req.app.get('io').emit('employee:changed', { action: 'updated', employee: emp });
        }

        res.json({ success: true, message: 'Updated in memory for this server run; update the code data to keep it after restart.', data: emp });
      } catch (err) {
        console.error('Update employee error:', err);
        res.status(500).json({ success: false, message: 'Failed to update employee.' });
      }
    });

    // DELETE /api/employees/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = STATIC_EMPLOYEES.findIndex((employee) => String(employee.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Employee not found.' });
        STATIC_EMPLOYEES.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('employee:changed', { action: 'deleted', id });
        }

        res.json({ success: true, message: 'Removed in memory for this server run; update the code data to keep it after restart.' });
      } catch (err) {
        console.error('Delete employee error:', err);
        res.status(500).json({ success: false, message: 'Failed to delete employee.' });
      }
    });


    return router;
  })();
  api.use('/employees', employeesRouter);

  const documentsRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/documents
    router.get('/', verifyToken, async (req, res) => {
      try {
        const { search, category } = req.query;
        if ((search != null && (typeof search !== 'string' || search.length > 200)) ||
            (category != null && (typeof category !== 'string' || category.length > 60))) {
          return res.status(400).json({ success: false, message: 'Invalid document search filters.' });
        }
        let docs = STATIC_DOCUMENTS.slice().sort((a, b) => a.doc_number.localeCompare(b.doc_number));

        if (search && search.trim()) {
          const q = search.trim().toLowerCase();
          docs = docs.filter(d =>
            (d.title || '').toLowerCase().includes(q) ||
            (d.doc_number || '').toLowerCase().includes(q) ||
            (d.category || '').toLowerCase().includes(q) ||
            (d.file_location || '').toLowerCase().includes(q)
          );
        }

        if (category && category !== 'All') {
          docs = docs.filter(d => d.category === category);
        }

        const allCategories = Array.from(new Set(STATIC_DOCUMENTS.map((doc) => doc.category)));

        res.json({
          success: true,
          data: docs,
          categories: allCategories
        });
      } catch (err) {
        console.error('Fetch docs error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve controlled documents.' });
      }
    });

    // POST /api/documents (Admin only)
    router.post('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { doc_number, title, category, revision, updated_date, file_location } = req.body;
        if (!validText(doc_number, 50) || !validText(title, 200) ||
            !validText(category, 60) || !validText(file_location, 255) ||
            (revision != null && !validText(revision, 10)) ||
            (updated_date != null && !validIsoDate(updated_date))) {
          return res.status(400).json({ success: false, message: 'Invalid document details.' });
        }

        if (STATIC_DOCUMENTS.some((document) => document.doc_number === doc_number.trim())) {
          return res.status(400).json({ success: false, message: 'A document with this number already exists.' });
        }

        const uDate = updated_date || new Date().toISOString().slice(0, 10);
        const rev = revision ? revision.trim().toUpperCase() : 'A';

        const newDoc = {
          id: Math.max(0, ...STATIC_DOCUMENTS.map((document) => Number(document.id) || 0)) + 1,
          doc_number: doc_number.trim(),
          title: title.trim(),
          category: category.trim(),
          revision: rev,
          updated_date: uDate,
          file_location: file_location.trim(),
          created_by: req.user.id
        };
        STATIC_DOCUMENTS.push(newDoc);

        if (req.app.get('io')) {
          req.app.get('io').emit('document:changed', { action: 'created', document: newDoc });
        }

        res.status(201).json({ success: true, message: 'Added in memory for this server run; update the code data to keep it after restart.', data: newDoc });
      } catch (err) {
        console.error('Add document error:', err);
        res.status(500).json({ success: false, message: 'Failed to add document.' });
      }
    });

    // PUT /api/documents/:id (Admin only)
    router.put('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { title, category, revision, updated_date, file_location } = req.body;

        if (!validText(title, 200) || !validText(category, 60) ||
            !validText(file_location, 255) ||
            (revision != null && !validText(revision, 10)) ||
            (updated_date != null && !validIsoDate(updated_date))) {
          return res.status(400).json({ success: false, message: 'Invalid document details.' });
        }

        const uDate = updated_date || new Date().toISOString().slice(0, 10);
        const rev = (revision || 'A').trim().toUpperCase();

        const doc = STATIC_DOCUMENTS.find((document) => String(document.id) === String(id));
        if (!doc) return res.status(404).json({ success: false, message: 'Document not found.' });
        Object.assign(doc, { title: title.trim(), category: category.trim(), revision: rev, updated_date: uDate, file_location: file_location.trim() });

        if (req.app.get('io')) {
          req.app.get('io').emit('document:changed', { action: 'updated', document: doc });
        }

        res.json({ success: true, message: 'Updated in memory for this server run; update the code data to keep it after restart.', data: doc });
      } catch (err) {
        console.error('Update document error:', err);
        res.status(500).json({ success: false, message: 'Failed to update document.' });
      }
    });

    // DELETE /api/documents/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = STATIC_DOCUMENTS.findIndex((document) => String(document.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Document not found.' });
        STATIC_DOCUMENTS.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('document:changed', { action: 'deleted', id });
        }

        res.json({ success: true, message: 'Removed in memory for this server run; update the code data to keep it after restart.' });
      } catch (err) {
        console.error('Delete document error:', err);
        res.status(500).json({ success: false, message: 'Failed to delete document.' });
      }
    });


    return router;
  })();
  api.use('/documents', documentsRouter);

  // GET /api/assets (Authenticated inventory)
  const assetsRouter = express.Router();
  assetsRouter.get('/', verifyToken, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, columns: ASSET_COLUMNS, data: STATIC_ASSETS });
  });
  // PATCH /api/assets/:index/assignment (Admin-only User Id / Name editing)
  assetsRouter.patch('/:index/assignment', verifyToken, requireAdmin, (req, res) => {
    const indexText = req.params.index;
    const index = Number(indexText);
    const allowedFields = new Set(['User Id', 'Name']);
    if (!/^\d+$/.test(indexText) || !Number.isSafeInteger(index) || index < 0 || index >= STATIC_ASSETS.length) {
      return res.status(404).json({ success: false, message: 'Asset record not found.' });
    }
    if (Object.keys(req.body).some((key) => !allowedFields.has(key)) ||
        !validText(req.body['User Id'], 100, true) || !validText(req.body.Name, 120, true)) {
      return res.status(400).json({ success: false, message: 'Only valid User Id and Name values can be updated.' });
    }
    const asset = STATIC_ASSETS[index];
    asset['User Id'] = req.body['User Id'].trim();
    asset.Name = req.body.Name.trim();
    res.json({ success: true, message: 'Asset assignment updated for this server run.', data: asset });
  });
  api.use('/assets', assetsRouter);

  const helpdeskRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/helpdesk
    router.get('/', verifyToken, async (req, res) => {
      try {
        const { mine, status } = req.query;
        let tickets = MEMORY.tickets.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));

        if (mine === 'true') {
          tickets = tickets.filter(t => t.submitted_by === req.user.id);
        }

        if (status && status !== 'All') {
          tickets = tickets.filter(t => t.status === status);
        }

        res.json({ success: true, data: tickets });
      } catch (err) {
        console.error('Fetch helpdesk error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve helpdesk tickets.' });
      }
    });

    // POST /api/helpdesk (Employees & Admins)
    router.post('/', verifyToken, async (req, res) => {
      try {
        const { kind, priority, title, machine_or_location, detail } = req.body;
        const validKinds = ['Maintenance', 'IT', 'Stores', 'Safety hazard', 'Other'];
        if (!validText(title, 160) ||
            (kind != null && !validKinds.includes(kind)) ||
            (priority != null && !['Normal', 'Urgent'].includes(priority)) ||
            (machine_or_location != null && !validText(machine_or_location, 100, true)) ||
            (detail != null && !validText(detail, 10000, true))) {
          return res.status(400).json({ success: false, message: 'Invalid helpdesk request details.' });
        }

        const ticket_ref = 'T-' + crypto.randomBytes(4).toString('hex').toUpperCase();
        const k = kind || 'Maintenance';
        const prio = priority || 'Normal';
        const loc = (machine_or_location || '').trim();
        const det = (detail || '').trim();

        const newTicket = {
          id: nextId(MEMORY.tickets),
          ticket_ref,
          kind: k,
          priority: prio,
          title: title.trim(),
          machine_or_location: loc,
          detail: det,
          status: 'Open',
          submitted_by: req.user.id,
          submitter_name: req.user.full_name,
          created_at: new Date().toISOString()
        };
        MEMORY.tickets.push(newTicket);

        if (req.app.get('io')) {
          req.app.get('io').emit('ticket:created', newTicket);
        }

        res.status(201).json({ success: true, message: 'Helpdesk request registered for this server run.', data: newTicket });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to create helpdesk ticket.' });
      }
    });

    // PATCH /api/helpdesk/:id/status (Admin only)
    router.patch('/:id/status', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;

        const validStatuses = ['Open', 'In progress', 'Done'];
        if (!validStatuses.includes(status)) {
          return res.status(400).json({ success: false, message: 'Invalid status. Must be Open, In progress, or Done.' });
        }

        const ticket = MEMORY.tickets.find((item) => String(item.id) === String(id));
        if (!ticket) return res.status(404).json({ success: false, message: 'Ticket not found.' });
        ticket.status = status;

        if (req.app.get('io')) {
          req.app.get('io').emit('ticket:status_changed', { id, status });
        }

        res.json({ success: true, message: 'Ticket status updated to ' + status });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to update ticket status.' });
      }
    });

    // DELETE /api/helpdesk/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.tickets.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Ticket not found.' });
        MEMORY.tickets.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('ticket:deleted', { id });
        }

        res.json({ success: true, message: 'Helpdesk ticket deleted.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete ticket.' });
      }
    });


    return router;
  })();
  api.use('/helpdesk', helpdeskRouter);

  const suggestionsRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/suggestions
    router.get('/', verifyToken, async (req, res) => {
      try {
        const isAdmin = req.user.role === 'admin';
        let suggestions = MEMORY.suggestions.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));

        if (!isAdmin) {
          // Employees see only their own suggestions
          suggestions = suggestions.filter(s => s.submitted_by === req.user.id);
        }

        const formatted = suggestions.map(s => ({
          ...s,
          submitter_name: s.submitter_name || (s.submitted_by === req.user.id ? `${req.user.full_name} (you)` : 'Colleague')
        }));

        res.json({ success: true, data: formatted });
      } catch (err) {
        console.error('Fetch suggestions error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve suggestions.' });
      }
    });

    // POST /api/suggestions
    router.post('/', verifyToken, async (req, res) => {
      try {
        const { category, suggestion_text } = req.body;
        const categories = ['Safety', 'Process improvement', 'Workplace', 'Other'];
        if (!validText(suggestion_text, 10000) ||
            (category != null && !categories.includes(category))) {
          return res.status(400).json({ success: false, message: 'Invalid suggestion details.' });
        }

        const cat = category || 'General';
        const text = suggestion_text.trim();

        const newSuggestion = {
          id: nextId(MEMORY.suggestions),
          category: cat,
          suggestion_text: text,
          submitted_by: req.user.id,
          submitter_name: req.user.full_name,
          created_at: new Date().toISOString()
        };
        MEMORY.suggestions.push(newSuggestion);

        if (req.app.get('io')) {
          const io = req.app.get('io');
          io.to('admins').emit('suggestion:created', newSuggestion);
          io.to(`user:${req.user.id}`).emit('suggestion:created', newSuggestion);
        }

        res.status(201).json({ success: true, message: 'Thank you! Your idea has been sent to plant management for this server run.', data: newSuggestion });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to submit suggestion.' });
      }
    });

    // DELETE /api/suggestions/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.suggestions.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Suggestion not found.' });
        MEMORY.suggestions.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').to('admins').emit('suggestion:deleted', { id });
        }

        res.json({ success: true, message: 'Suggestion removed.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete suggestion.' });
      }
    });


    return router;
  })();
  api.use('/suggestions', suggestionsRouter);

  const hrRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/hr
    router.get('/', verifyToken, async (req, res) => {
      try {
        const hrDocs = STATIC_DOCUMENTS.filter(d => d.category === 'HR' || (d.category === 'Forms' && (d.doc_number || '').includes('HR')));
        const hrPeople = STATIC_EMPLOYEES.filter(e => e.department === 'HR' || (e.designation || '').toLowerCase().includes('safety'));
        const holidays = MEMORY.holidays.slice().sort((a, b) => String(a.holiday_date).localeCompare(String(b.holiday_date)));

        res.json({
          success: true,
          data: {
            documents: hrDocs,
            contacts: hrPeople,
            holidays: holidays || []
          }
        });
      } catch (err) {
        console.error('Fetch HR data error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve HR and holiday information.' });
      }
    });

    // POST /api/hr/holidays (Admin only)
    router.post('/holidays', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { holiday_date, name, day_name } = req.body;
        if (!validIsoDate(holiday_date) || !validText(name, 100)) {
          return res.status(400).json({ success: false, message: 'Invalid holiday details.' });
        }

        const d = new Date(holiday_date + 'T00:00:00');
        const calculatedDay = d.toLocaleDateString('en-US', { weekday: 'long' });

        const newHoliday = {
          id: nextId(MEMORY.holidays),
          holiday_date,
          name: name.trim(),
          day_name: calculatedDay
        };
        MEMORY.holidays.push(newHoliday);

        if (req.app.get('io')) {
          req.app.get('io').emit('holiday:changed', { action: 'created', holiday: newHoliday });
        }

        res.status(201).json({ success: true, message: 'Holiday added for this server run.', data: newHoliday });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to add holiday.' });
      }
    });

    // DELETE /api/hr/holidays/:id (Admin only)
    router.delete('/holidays/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.holidays.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Holiday not found.' });
        MEMORY.holidays.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('holiday:changed', { action: 'deleted', id });
        }

        res.json({ success: true, message: 'Holiday removed.' });
      } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete holiday.' });
      }
    });


    return router;
  })();
  api.use('/hr', hrRouter);

  const linksRouter = (() => {
    const router = express.Router();
    router.param('id', validRowId);

    // GET /api/links
    router.get('/', verifyToken, async (req, res) => {
      try {
        const links = MEMORY.links.slice().sort((a, b) => a.sort_order - b.sort_order || a.id - b.id);

        // Group links by group_name
        const groupMap = {};
        links.forEach(l => {
          const g = l.group_name || 'General';
          if (!groupMap[g]) groupMap[g] = [];
          groupMap[g].push(l);
        });

        const grouped = Object.keys(groupMap).map(g => ({
          group: g,
          items: groupMap[g]
        }));

        res.json({ success: true, data: grouped, flat: links });
      } catch (err) {
        console.error('Fetch links error:', err);
        res.status(500).json({ success: false, message: 'Failed to retrieve quick links.' });
      }
    });

    // POST /api/links (Admin only)
    router.post('/', verifyToken, requireAdmin, async (req, res) => {
      try {
        const { group_name, title, subtext, url, sort_order } = req.body;
        const order = sort_order == null ? 1 : Number(sort_order);
        if (!validText(group_name, 60) || !validText(title, 100) ||
            !validHttpUrl(url) || (subtext != null && !validText(subtext, 200, true)) ||
            !Number.isInteger(order) || order < 0 || order > 1000000) {
          return res.status(400).json({ success: false, message: 'Invalid quick link details.' });
        }

        const newLink = {
          id: nextId(MEMORY.links),
          group_name: group_name.trim(),
          title: title.trim(),
          subtext: (subtext || '').trim(),
          url: url.trim(),
          sort_order: order
        };
        MEMORY.links.push(newLink);

        if (req.app.get('io')) {
          req.app.get('io').emit('link:changed', { action: 'created', link: newLink });
        }

        res.status(201).json({ success: true, message: 'Quick link added successfully.', data: newLink });
      } catch (err) {
        console.error('Add link error:', err);
        res.status(500).json({ success: false, message: 'Failed to add quick link.' });
      }
    });

    // PUT /api/links/:id (Admin only)
    router.put('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { group_name, title, subtext, url, sort_order } = req.body;

        const order = sort_order == null ? 1 : Number(sort_order);
        if (!validText(group_name, 60) || !validText(title, 100) ||
            !validHttpUrl(url) || (subtext != null && !validText(subtext, 200, true)) ||
            !Number.isInteger(order) || order < 0 || order > 1000000) {
          return res.status(400).json({ success: false, message: 'Invalid quick link details.' });
        }

        const link = MEMORY.links.find((item) => String(item.id) === String(id));
        if (!link) return res.status(404).json({ success: false, message: 'Quick link not found.' });
        Object.assign(link, { group_name: group_name.trim(), title: title.trim(), subtext: (subtext || '').trim(), url: url.trim(), sort_order: order });

        if (req.app.get('io')) {
          req.app.get('io').emit('link:changed', { action: 'updated', link });
        }

        res.json({ success: true, message: 'Quick link updated successfully.', data: link });
      } catch (err) {
        console.error('Update link error:', err);
        res.status(500).json({ success: false, message: 'Failed to update quick link.' });
      }
    });

    // DELETE /api/links/:id (Admin only)
    router.delete('/:id', verifyToken, requireAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const index = MEMORY.links.findIndex((item) => String(item.id) === String(id));
        if (index < 0) return res.status(404).json({ success: false, message: 'Quick link not found.' });
        MEMORY.links.splice(index, 1);

        if (req.app.get('io')) {
          req.app.get('io').emit('link:changed', { action: 'deleted', id });
        }

        res.json({ success: true, message: 'Quick link deleted.' });
      } catch (err) {
        console.error('Delete link error:', err);
        res.status(500).json({ success: false, message: 'Failed to delete quick link.' });
      }
    });


    return router;
  })();
  api.use('/links', linksRouter);
  return api;
};
