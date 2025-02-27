// Create an axios interceptor wrapper: src/utils/api.ts
  
import axios from "axios";
import { updateToken } from "./sessionManager";

const api = axios.create({
  baseURL: "http://localhost:8000",
});

// Response interceptor for token rotation
api.interceptors.response.use(
  (response) => {
    // Check if response contains a new token
    if (response.data && response.data.token) {
      // Update the token in localStorage
      updateToken(response.data.token);
      
      // If token was rotated, log it (optional)
      if (response.data.token_status === "Token rotated") {
        console.log("Session token has been rotated for security");
      }
    }
    return response;
  },
  (error) => {
    // Handle session expiration
    if (error.response && error.response.status === 401) {
      // Clear session data
      localStorage.removeItem("authToken");
      localStorage.removeItem("username");
      sessionStorage.removeItem("masterPassword");
      
      // Redirect to login page
      window.location.href = "/login";
      return Promise.reject(new Error("Session expired. Please log in again."));
    }
    return Promise.reject(error);
  }
);

export default api;