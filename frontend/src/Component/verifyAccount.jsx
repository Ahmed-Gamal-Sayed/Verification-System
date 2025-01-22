import React, { useRef, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";


export default function VerifyAccount() {
  const [code, setCode] = useState(['', '', '', '', '', '']);
  const inputRefs = useRef([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const nav = useNavigate();

  const handleChange = (index, value) => {
    const newCode = [...code];

    if (value.length > 1) {
      const pastedCode = value.slice(0, 6).split('');
      for (let i = 0; i < 6; i++) {
        newCode[i] = pastedCode[i] || '';
      }
      setCode(newCode);

      const lastFilledIndex = newCode.findLastIndex((digit) => digit !== '');
      const focusIndex = lastFilledIndex < 5 ? lastFilledIndex + 1 : 5;
      inputRefs.current[focusIndex].focus();
    } else {
      newCode[index] = value;
      setCode(newCode);

      if (value && index < 5) {
        inputRefs.current[index + 1].focus();
      }
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      inputRefs.current[index - 1].focus();
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const response = await axios.post("http://localhost:4000/api/verify-email", code);

      // Handle the response (e.g., save token, navigate to another page)
      console.log("Verification Successful:", response.data);
      setLoading(false);
      nav('/changepassword');
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
            <h2 className='title'>Verify Your Email</h2>
            <p className="p-verify">Enter the 6-digit code sent to your email address</p>
            <div className="d-flex justify-content-evenly gap-3">
              {code.map((digit, index) => (
                <input
                  key={index}
                  ref={(eL) => { inputRefs.current[index] = eL }}
                  type='text'
                  maxLength='1'
                  className='code'
                  required
                  value={digit}
                  onChange={(e) => handleChange(index, e.target.value)}
                  onKeyDown={(e) => handleKeyDown(index, e)}
                />
              ))}
            </div>

            {error !== '' ? <p className="error">{error}</p> : ''}
            <button type="submit" className="btn-submit">{loading ? "Verifying..." : "Verify"}</button>
          </fieldset>
        </form>
      </div>
    </>
  );
}
