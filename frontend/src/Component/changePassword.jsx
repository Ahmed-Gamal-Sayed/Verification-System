import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

import urlPath from '../App';

export default function ChangePassword() {
  const [formData, setFormData] = useState({ password: "", repassword: '' });
  const [error, setError] = useState("");
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
      const response = await axios.post(urlPath + '/change-password', formData);

      // Handle the response (e.g., save token, navigate to another page)
      console.log("Change Password Successful:", response.data);
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
            <h2 className='title'>Change Password</h2>
            <input type='password' className='input-field' name="password" placeholder="Enter your password" required value={formData.password} onChange={handleChange} />
            <input type='password' className='input-field' name="repassword" placeholder="Enter your confirm password" required value={formData.repassword} onChange={handleChange} />

            {error && <div className="alert alert-danger" role="alert">{error}</div>}
            <button type="submit" className="btn-submit">{loading ? "Submitting..." : "Submit"}</button>
          </fieldset>
        </form>
      </div>
    </>
  );
}
