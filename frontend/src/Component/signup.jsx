import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";


export default function Signup() {
  const [formData, setFormData] = useState({ fullname: '', email: '', password: '', repassword: '' });
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
      const response = await axios.post("http://localhost:4000/api/signup", formData);
      
      // Handle the response (e.g., save token, navigate to another page)
      console.log("Create Account Successful: ", response.data);
      setLoading(false);
      nav('/signin');
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
            <h2 className='title'>Create Account</h2>

            <input type='text' className='input-field' name="fullname" placeholder="Enter your full name" required value={formData.fullname} onChange={handleChange} />
            <input type='email' className='input-field' name="email" placeholder="Enter your email" required value={formData.email} onChange={handleChange} />
            <input type='password' className='input-field' name="password" placeholder="Enter your password" required value={formData.password} onChange={handleChange} />
            <input type='password' className='input-field' name="repassword" placeholder="Enter your confirm password" required value={formData.repassword} onChange={handleChange} />

            {error !== '' ? <p className="error">{error}</p> : ''}
            <button type="submit" className="btn-submit">{loading ? "Signning up..." : "Sign up"}</button>
            <p className="signup-link">Already have an account? <a href="/signin">Sign in</a></p>
          </fieldset>
        </form>
      </div>
    </>
  );
}
