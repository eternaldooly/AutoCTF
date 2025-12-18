import React from 'react'
import ReactDOM from 'react-dom/client'
import { GoogleOAuthProvider } from '@react-oauth/google'
import App from '../App.tsx'
import '../styles/globals.css'

const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID

const Root = (
  <React.StrictMode>
    {googleClientId ? (
      <GoogleOAuthProvider clientId={googleClientId}>
        <App />
      </GoogleOAuthProvider>
    ) : (
      <App />
    )}
  </React.StrictMode>
)

ReactDOM.createRoot(document.getElementById('root')!).render(Root)
