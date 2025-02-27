// Create a utility file: src/utils/sessionManager.ts

export const updateToken = (newToken: string | null) => {
    if (newToken) {
      localStorage.setItem("authToken", newToken);
      return newToken;
    }
    return localStorage.getItem("authToken");
  };