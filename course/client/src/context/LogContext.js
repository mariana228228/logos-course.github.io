import {createContext} from "react";

export const LogContext = createContext(
    {
        token: null,
        userId: null,
        login: null,
        logout: null,
        isAuthenticated: false
    }
)