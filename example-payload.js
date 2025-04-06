// This is an example file for testing the Extractify tool
// It contains various secrets, endpoints, and API routes

// API Configuration
const API_CONFIG = {
  base_url: "https://api.example.com/v1",
  api_key: "api_key_12345abcdef6789ghijkl0123456789",
  timeout: 30000,
};

// Secret Keys (for demonstration purposes only)
const SECRET_KEYS = {
  aws_access_key: "AKIAIOSFODNN7EXAMPLE",
  aws_secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  github_token: "ghp_aBc123DeFgHiJkLmNoPqRsTuVwXyZ0123456789",
  stripe_key: "sk_live_abcdefghijklmnopqrstuvwxyz12345678901234",
  jwt_secret: "jwt_secret_key_for_signing_tokens_1234567890",
  database: {
    mongodb_uri: "mongodb://admin:password123@mongodb.example.com:27017/mydb",
    password: "super_secure_db_password!",
  },
};

// API Endpoints
function fetchUserData(userId) {
  return fetch(`${API_CONFIG.base_url}/users/${userId}`, {
    headers: {
      Authorization: `Bearer ${SECRET_KEYS.jwt_secret}`,
      "Content-Type": "application/json",
    },
  });
}

// More endpoints in comments
// GET /api/v1/products
// POST /api/v1/orders
// PUT /api/v2/users/profile
// DELETE /api/v1/comments/:id

// Internal endpoints
const INTERNAL_ENDPOINTS = {
  auth: "/auth/login",
  register: "/auth/register",
  products: "/api/products",
  dashboard: "/admin/dashboard",
  settings: "/settings/account",
  logout: "/auth/logout",
};

// URL examples
const externalUrls = [
  "https://example.com/path/to/resource",
  "https://api.service.com/v2/data",
  "https://cdn.example.org/assets/main.js",
  "https://maps.service.net/location?lat=123&lng=456",
];

// GraphQL endpoint
const graphqlEndpoint = "/graphql";

// Server configuration
const serverConfig = {
  ip_address: "192.168.1.100",
  port: 3000,
  environment: "production",
  log_level: "info",
};

console.log("Config loaded successfully");
