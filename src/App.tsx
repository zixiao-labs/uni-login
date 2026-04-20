import { ChenRouter, Route, Routes } from 'chen-the-dawnstreak';
import Layout from './pages/_layout';
import Index from './pages/index';
import Login from './pages/login';
import Register from './pages/register';
import OauthCallback from './pages/oauth/callback';
import OauthAuthorize from './pages/oauth/authorize';

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
