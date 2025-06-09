import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import WaitlistModal from './WaitlistModal';

const Hero: React.FC = () => {
  const [isWaitlistModalOpen, setIsWaitlistModalOpen] = useState(false);
  return (
    <section className="pt-8 pb-8 md:pt-19.5 md:pb-24 w-full overflow-x-hidden bg-white">
      <div className="container-custom mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col-reverse md:grid md:grid-cols-2 gap-10 items-center w-full">
          <div className="order-2 md:order-1 w-full">
            <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-navy leading-tight">
              Meaningful <span className="text-teal">Connections</span> Within Your Trusted Circle
            </h1>
            <p className="text-lg mb-8 text-navy/80 max-w-lg">
              Connect with like-minded individuals in your community for friendship, romance, or professional networking - all within trusted groups you already belong to.
            </p>
            <div className="flex flex-col sm:flex-row gap-4">
              <button
                type="button"
                onClick={() => setIsWaitlistModalOpen(true)}
                className="btn-primary flex items-center justify-center gap-2"
              >
                Join Waitlist <ArrowRight size={18} />
              </button>
              <Link to="/#how-it-works" className="btn-outline flex items-center justify-center">
                Learn More
              </Link>
            </div>
          </div>
          <div className="order-1 md:order-2 relative w-full flex justify-center md:block overflow-visible">
            <div className="absolute -top-15 -left-20 w-64 h-64 bg-teal/20 rounded-full blur-3xl pointer-events-none max-w-full max-h-full" style={{maxWidth:'100vw',maxHeight:'64vh'}}></div>
            <div className="absolute -bottom-15 -right-20 w-64 h-64 bg-orange/20 rounded-full blur-3xl pointer-events-none max-w-full max-h-full" style={{maxWidth:'100vw',maxHeight:'64vh'}}></div>
            
            <div className="relative z-10 rounded-2xl bg-white p-5 shadow-lg border border-gray-100">
              <div className="bg-cream rounded-lg p-4 mb-4">
                <div className="flex justify-between items-center mb-3">
                  <h3 className="font-poppins text-navy font-medium">Your Match Request</h3>
                  <span className="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">New!</span>
                </div>
                <div className="flex items-center gap-4">
                  <div className="w-16 h-16 rounded-full bg-teal/30 flex items-center justify-center">
                    <svg className="w-8 h-8 text-teal" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                      <circle cx="9" cy="7" r="4" />
                      <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
                      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                    </svg>
                  </div>
                  <div>
                    <h4 className="font-semibold">Sarah Thompson</h4>
                    <p className="text-sm text-gray-600">Lagos Tech Circle - Business</p>
                  </div>
                </div>
                
                <div className="mt-4 grid grid-cols-2 gap-4">
                  <button className="bg-teal text-white py-2 rounded-lg hover:bg-teal/90 transition-colors">
                    Accept
                  </button>
                  <button className="bg-gray-200 text-gray-700 py-2 rounded-lg hover:bg-gray-300 transition-colors">
                    Decline
                  </button>
                </div>
              </div>
              
              <div className="space-y-3 mb-2">
                <div className="flex items-center gap-3">
                  <span className="w-10 h-10 bg-orange/20 rounded-full flex items-center justify-center text-orange">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className="w-5 h-5">
                      <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" />
                      <circle cx="12" cy="10" r="3" />
                    </svg>
                  </span>
                  <div className="flex-1 bg-gray-100 h-12 rounded-lg animate-pulse-soft"></div>
                </div>
                
                <div className="flex items-center gap-3">
                  <span className="w-10 h-10 bg-teal/20 rounded-full flex items-center justify-center text-teal">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className="w-5 h-5">
                      <circle cx="12" cy="12" r="10" />
                      <polyline points="12 6 12 12 16 14" />
                    </svg>
                  </span>
                  <div className="flex-1 bg-gray-100 h-12 rounded-lg animate-pulse-soft"></div>
                </div>
                
                <div className="flex items-center gap-3">
                  <span className="w-10 h-10 bg-navy/20 rounded-full flex items-center justify-center text-navy">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" className="w-5 h-5">
                      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                      <circle cx="9" cy="7" r="4" />
                      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                    </svg>
                  </span>
                  <div className="flex-1 bg-gray-100 h-12 rounded-lg animate-pulse-soft"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <WaitlistModal 
        isOpen={isWaitlistModalOpen} 
        onClose={() => setIsWaitlistModalOpen(false)} 
      />
    </section>
  );
};

export default Hero;
