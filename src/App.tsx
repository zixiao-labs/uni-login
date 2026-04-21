import { ChenRouter, Route, Routes } from 'chen-the-dawnstreak';
import Layout from './pages/_layout';
import Index from './pages/index';
import Login from './pages/login';
import Register from './pages/register';
import OauthCallback from './pages/oauth/callback';
import OauthAuthorize from './pages/oauth/authorize';

/**
 * Root application component that defines the client-side routing tree wrapped by the app layout.
 *
 * Renders routes for the index page, login, register, OAuth authorize, and OAuth callback paths.
 *
 * @returns A React element containing the configured router and nested routes
 */
export default function App() {
  return (
    <ChenRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Index />} />
          <Route path="login" element={<Login />} />
          <Route path="register" element={<Register />} />
          <Route path="oauth/authorize" element={<OauthAuthorize />} />
          <Route path="oauth/callback" element={<OauthCallback />} />
        </Route>
      </Routes>
    </ChenRouter>
  );
}
