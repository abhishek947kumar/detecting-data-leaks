/**
 * Seed Data for Detecting Data Leaks Project
 * Includes realistic e-commerce products, demo users, and synthetic honeytokens.
 */

const products = [
  {
    name: 'TitanSec Hardware Security Key Pro',
    category: 'Cybersecurity',
    price: 69.99,
    stock: 45,
    rating: 4.9,
    description: 'FIDO2 & U2F Certified USB-C hardware authenticator with tamper-resistant cryptographic element.',
    image_url: 'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=500&auto=format&fit=crop&q=60'
  },
  {
    name: 'CipherVault Encrypted NVMe SSD 2TB',
    category: 'Storage',
    price: 249.99,
    stock: 28,
    rating: 4.8,
    description: 'Hardware AES-X 256-bit encrypted solid-state drive with self-destruct firmware protection.',
    image_url: 'https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?w=500&auto=format&fit=crop&q=60'
  },
  {
    name: 'Aegis Quantum Mesh Router v6',
    category: 'Networking',
    price: 329.00,
    stock: 19,
    rating: 4.7,
    description: 'Tri-band Wi-Fi 7 secure gateway with deep packet inspection and integrated intrusion prevention firewall.',
    image_url: 'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=500&auto=format&fit=crop&q=60'
  },
  {
    name: 'Krypton Privacy Glass OLED Laptop 16"',
    category: 'Computers',
    price: 1899.99,
    stock: 12,
    rating: 4.9,
    description: 'Workstation laptop featuring an electronically polarizable anti-peep display and hardware kill switches.',
    image_url: 'https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=500&auto=format&fit=crop&q=60'
  },
  {
    name: 'StealthShield Faraday Data Pouch',
    category: 'Accessories',
    price: 39.50,
    stock: 80,
    rating: 4.6,
    description: 'Military-grade RF and EMP blocking fabric bag to guard phones and cards from remote skimming.',
    image_url: 'https://images.unsplash.com/photo-1544816155-12df9643f363?w=500&auto=format&fit=crop&q=60'
  },
  {
    name: 'Sentient SOC Enterprise Sensor Node',
    category: 'Cybersecurity',
    price: 499.00,
    stock: 15,
    rating: 4.8,
    description: 'Autonomous network probe running continuous contextual telemetry and anomaly detection.',
    image_url: 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=500&auto=format&fit=crop&q=60'
  }
];

const demoUsers = [
  {
    username: 'alice_smith',
    email: 'alice.smith@securecloud.org',
    password: 'Password123!',
    role: 'customer',
    fullName: 'Alice Smith',
    phone: '+1 (555) 234-5678',
    address: '742 Evergreen Terrace, Springfield, OR',
    creditCard: '4532718293847561', // Visa
    balance: 1450.00
  },
  {
    username: 'bob_developer',
    email: 'bob.dev@fintechcorp.io',
    password: 'DevSecurePass99!',
    role: 'customer',
    fullName: 'Robert Miller',
    phone: '+1 (555) 890-1234',
    address: '100 Market Street, San Francisco, CA',
    creditCard: '5424182938475612', // Mastercard
    balance: 2890.50
  },
  {
    username: 'soc_admin',
    email: 'security.lead@dlp-sentinel.cloud',
    password: 'SuperAdminPass2026!#',
    role: 'admin',
    fullName: 'Chief Information Security Officer',
    phone: '+1 (555) 999-0001',
    address: 'Cloud Operations Center, Austin, TX',
    creditCard: '378282246310005', // Amex
    balance: 99999.00
  }
];

const honeytokens = [
  {
    name: 'Honeytoken Fake Customer 1',
    username: 'honey_exec_ceo',
    email: 'fake.ceo@honeypot-decoy.internal',
    creditCard: '4000001234567890',
    warning: 'HONEYTOKEN ACCESSED - TRACER DISPATCHED'
  },
  {
    name: 'Honeytoken Secret Admin Token',
    username: 'super_backdoor_admin',
    email: 'decoy.admin@sentinel-trap.internal',
    creditCard: '5105105105105100',
    warning: 'UNAUTHORIZED PRIVILEGE ACCESS TRAP TRIGGERED'
  }
];

module.exports = {
  products,
  demoUsers,
  honeytokens
};
