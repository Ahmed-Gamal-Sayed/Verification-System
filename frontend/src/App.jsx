import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import React from 'react';
import Signup from './Component/signup.jsx'
import Signin from './Component/signin.jsx'
import ChangePassword from './Component/changePassword.jsx'
import ForgetPassword from './Component/forgetPassword.jsx'
import VerifyAccount from './Component/verifyAccount.jsx'
import Home from './Component/home.jsx';
import Dashboard from './Component/dashboard.jsx';



const NotFound = () => {
  return (<h1 className='notFound'>404 - Not Found Page!</h1>);
}

export const urlPath = 'http://localhost:4000/api/auth';

export default function App() {
  return (
    <>
      <Router>
        <Routes>
          <Route path='/' element={<Home />} />
          <Route path='/dashboard' element={<Dashboard />} />
          <Route path='/signin' element={<Signin />} />
          <Route path='/signup' element={<Signup />} />
          <Route path='/forgetpassword' element={<ForgetPassword />} />
          <Route path='/changepassword' element={<ChangePassword />} />
          <Route path='/verify-email' element={<VerifyAccount />} />
          <Route path='*' element={<NotFound />} />
        </Routes>
      </Router>
    </>
  );
}
