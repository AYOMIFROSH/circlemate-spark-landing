import React, { useState } from 'react';
import { X, Mail, User, Briefcase, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

interface WaitlistModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface FormData {
  firstName: string;
  lastName: string;
  email: string;
  interest: string;
}

const WaitlistModal: React.FC<WaitlistModalProps> = ({ isOpen, onClose }) => {
  const [formData, setFormData] = useState<FormData>({
    firstName: '',
    lastName: '',
    email: '',
    interest: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [errors, setErrors] = useState<Partial<FormData>>({});
  const [apiError, setApiError] = useState('');
  

const NEXT_PUBLIC_API_URL =
  process.env.NODE_ENV === "production"
    ? "https://circlemate-spark-landing-jet.vercel.app"
    : "http://localhost:3000";

  const validateForm = (): boolean => {
    const newErrors: Partial<FormData> = {};
    
    if (!formData.firstName.trim()) {
      newErrors.firstName = 'First name is required';
    }
    
    if (!formData.lastName.trim()) {
      newErrors.lastName = 'Last name is required';
    }
    
    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email';
    }
    
    if (!formData.interest) {
      newErrors.interest = 'Please select your interest';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) return;

    setIsSubmitting(true);
    setApiError('');

    try {
      const response = await fetch(`${NEXT_PUBLIC_API_URL}/api/waitlist/submit`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });

      const result = await response.json();

      if (response.ok && result.status === 'success') {
        console.log("Waitlist submission success:", result);
        setIsSuccess(true);
      } else {
        setApiError(result.message || 'Something went wrong. Please try again.');
      }
    } catch (error) {
      console.error("Submission error:", error);
      setApiError('Network error. Please check your connection and try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleInputChange = (field: keyof FormData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: undefined }));
    }
    if (apiError) {
      setApiError('');
    }
  };

  const resetAndClose = () => {
    setFormData({ firstName: '', lastName: '', email: '', interest: '' });
    setErrors({});
    setIsSuccess(false);
    setIsSubmitting(false);
    setApiError('');
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={resetAndClose}
      />
      
      {/* Modal */}
      <div className="relative w-full max-w-md mx-4 bg-white rounded-2xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-100">
          <div>
            <h2 className="text-2xl font-bold text-navy">Join Our Waitlist</h2>
            <p className="text-sm text-gray-600 mt-1">Be the first to know when we launch</p>
          </div>
          <button
            onClick={resetAndClose}
            className="p-2 hover:bg-gray-100 rounded-full transition-colors"
          >
            <X size={20} className="text-gray-500" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6">
          {!isSuccess ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* API Error */}
              {apiError && (
                <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
                  {apiError}
                </div>
              )}

              {/* Name Fields */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label htmlFor="firstName" className="text-sm font-medium text-gray-700">
                    First Name
                  </Label>
                  <div className="relative mt-1">
                    <Input
                      id="firstName"
                      type="text"
                      value={formData.firstName}
                      onChange={(e) => handleInputChange('firstName', e.target.value)}
                      className={`pl-10 ${errors.firstName ? 'border-red-500' : ''}`}
                      placeholder="Enter first name"
                    />
                    <User size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                  </div>
                  {errors.firstName && (
                    <p className="text-xs text-red-500 mt-1">{errors.firstName}</p>
                  )}
                </div>
                
                <div>
                  <Label htmlFor="lastName" className="text-sm font-medium text-gray-700">
                    Last Name
                  </Label>
                  <div className="relative mt-1">
                    <Input
                      id="lastName"
                      type="text"
                      value={formData.lastName}
                      onChange={(e) => handleInputChange('lastName', e.target.value)}
                      className={`pl-10 ${errors.lastName ? 'border-red-500' : ''}`}
                      placeholder="Enter last name"
                    />
                    <User size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                  </div>
                  {errors.lastName && (
                    <p className="text-xs text-red-500 mt-1">{errors.lastName}</p>
                  )}
                </div>
              </div>

              {/* Email Field */}
              <div>
                <Label htmlFor="email" className="text-sm font-medium text-gray-700">
                  Email Address
                </Label>
                <div className="relative mt-1">
                  <Input
                    id="email"
                    type="email"
                    value={formData.email}
                    onChange={(e) => handleInputChange('email', e.target.value)}
                    className={`pl-10 ${errors.email ? 'border-red-500' : ''}`}
                    placeholder="Enter your email"
                  />
                  <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                </div>
                {errors.email && (
                  <p className="text-xs text-red-500 mt-1">{errors.email}</p>
                )}
              </div>

              {/* Interest Field */}
              <div>
                <Label htmlFor="interest" className="text-sm font-medium text-gray-700">
                  Primary Interest
                </Label>
                <div className="relative mt-1">
                  <Select value={formData.interest} onValueChange={(value) => handleInputChange('interest', value)}>
                    <SelectTrigger className={`pl-10 ${errors.interest ? 'border-red-500' : ''}`}>
                      <SelectValue placeholder="Select your interest" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="friendship">Friendship</SelectItem>
                      <SelectItem value="romance">Romance</SelectItem>
                      <SelectItem value="professional">Professional Networking</SelectItem>
                      <SelectItem value="all">All of the above</SelectItem>
                    </SelectContent>
                  </Select>
                  <Briefcase size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
                </div>
                {errors.interest && (
                  <p className="text-xs text-red-500 mt-1">{errors.interest}</p>
                )}
              </div>

              {/* Submit Button */}
              <Button
                type="submit"
                disabled={isSubmitting}
                className="w-full bg-teal hover:bg-teal/90 text-white py-3 rounded-lg font-medium transition-all duration-200 mt-6"
              >
                {isSubmitting ? (
                  <div className="flex items-center justify-center gap-2">
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Joining Waitlist...
                  </div>
                ) : (
                  'Join Waitlist'
                )}
              </Button>
            </form>
          ) : (
            /* Success State */
            <div className="text-center py-8">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Check size={32} className="text-green-600" />
              </div>
              <h3 className="text-xl font-semibold text-navy mb-2">You're on the list!</h3>
              <p className="text-gray-600 mb-6">
                Thanks for joining our waitlist. We'll notify you as soon as we launch.
              </p>
              <Button
                onClick={resetAndClose}
                className="bg-teal hover:bg-teal/90 text-white px-8 py-2 rounded-lg font-medium"
              >
                Done
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default WaitlistModal;