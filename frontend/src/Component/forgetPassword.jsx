import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from 'react-router-dom';



export default function ForgetPassword() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  const handleChange = (e) => {
    setEmail({ ...email, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const response = await axios.post("http://localhost:4000/api/check-email", email);

      // Handle the response (e.g., save token, navigate to another page)
      console.log("Email Successful:", response.data);
      setLoading(false);
      nav('/verify-email');
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
            <h2 className='title'>Check Account</h2>
            <input type='email' className='input-field' name="email" placeholder="Enter your email" required value={email} onChange={handleChange} />

            {error !== '' ? <p className="error">{error}</p> : ''}
            <button type="submit" className="btn-submit">Checking Account</button>
            <p class="signup-link">Don't have an account? <a href="/signup">Sign up</a></p>
          </fieldset>
        </form>
      </div>
    </>
  );
}
