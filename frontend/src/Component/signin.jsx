import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';


export default function Signin() {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const response = await axios.post("http://localhost:4000/api/signin", formData);

      // Handle the response (e.g., save token, navigate to another page)
      console.log("Login Successful:", response.data);
      setLoading(false);
      nav('/dashboard');
    } catch (err) {
      setLoading(false);
      setError(err.response?.data?.message || "An error occurred");
    }
  };

  return (
    <>
      <div className='content'>
        <form onSubmit={handleSubmit}>
          <fieldset disabled={loading}>
            <h2 className='title'>Sign in</h2>
            <input type='email' className='input-field' name='email' placeholder="Enter your email" required value={formData.email} onChange={handleChange} />
            <input type='password' className='input-field' name='password' placeholder="Enter your password" required value={formData.password} onChange={handleChange} />
            <a href='/forgetpassword' className='forgetPassword'>Forget Password?</a>

            {error !== '' ? <p className="error">{error}</p> : ''}
            <button type="submit" className="btn-submit">{loading ? "Signning in..." : "Sign in"}</button>
            <p className="signup-link">Don't have an account? <a href="/signup">Sign up</a></p>
          </fieldset>
        </form>
      </div>
    </>
  );
}
