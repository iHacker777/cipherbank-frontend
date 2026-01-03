import React, { useState, useEffect } from 'react';
import { Share, X, ChevronUp, Smartphone } from 'lucide-react';

/**
 * iOS PWA Install Prompt Component
 * Detects iOS Safari and shows instructions for adding to home screen
 */
const IOSInstallPrompt = () => {
  const [showPrompt, setShowPrompt] = useState(false);
  const [isIOS, setIsIOS] = useState(false);
  const [isStandalone, setIsStandalone] = useState(false);
  const [isSafari, setIsSafari] = useState(false);

  useEffect(() => {
    // Detect iOS device
    const userAgent = window.navigator.userAgent.toLowerCase();
    const iOS = /iphone|ipad|ipod/.test(userAgent);
    setIsIOS(iOS);

    // Detect if already installed (running in standalone mode)
    const standalone = window.navigator.standalone ||
                      window.matchMedia('(display-mode: standalone)').matches;
    setIsStandalone(standalone);

    // Detect Safari browser
    const safari = /safari/.test(userAgent) && !/chrome|crios|fxios/.test(userAgent);
    setIsSafari(safari);

    // Check if user has already dismissed the prompt
    const dismissed = localStorage.getItem('ios-pwa-prompt-dismissed');
    const dismissedTime = dismissed ? parseInt(dismissed, 10) : 0;
    const daysSinceDismissed = (Date.now() - dismissedTime) / (1000 * 60 * 60 * 24);

    // Show prompt if:
    // 1. Running on iOS
    // 2. Not already in standalone mode
    // 3. Using Safari
    // 4. Either never dismissed OR dismissed more than 7 days ago
    if (iOS && !standalone && safari && (!dismissed || daysSinceDismissed > 7)) {
      // Wait 3 seconds before showing prompt
      setTimeout(() => {
        setShowPrompt(true);
      }, 3000);
    }
  }, []);

  const handleDismiss = () => {
    setShowPrompt(false);
    localStorage.setItem('ios-pwa-prompt-dismissed', Date.now().toString());
  };

  const handleNeverShow = () => {
    setShowPrompt(false);
    localStorage.setItem('ios-pwa-prompt-dismissed', '9999999999999'); // Far future date
  };

  if (!showPrompt || !isIOS || isStandalone || !isSafari) {
    return null;
  }

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 animate-fadeIn" />

      {/* Prompt Card */}
      <div className="fixed bottom-0 left-0 right-0 z-50 animate-slideUp">
        <div className="bg-white rounded-t-3xl shadow-2xl p-6 mx-4 mb-4 relative">
          {/* Close Button */}
          <button
            onClick={handleDismiss}
            className="absolute top-4 right-4 p-2 rounded-full hover:bg-gray-100 transition-colors"
            aria-label="Close"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>

          {/* Content */}
          <div className="pr-10">
            {/* Icon */}
            <div className="flex items-center gap-3 mb-4">
              <div className="w-14 h-14 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-2xl flex items-center justify-center shadow-lg">
                <Smartphone className="w-7 h-7 text-white" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-gray-900">Install CipherBank</h3>
                <p className="text-sm text-gray-600">Add to your home screen</p>
              </div>
            </div>

            {/* Instructions */}
            <div className="space-y-3 mb-6">
              <p className="text-gray-700 font-medium">
                Install this app for the best experience:
              </p>

              <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 space-y-3">
                {/* Step 1 */}
                <div className="flex items-start gap-3">
                  <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center flex-shrink-0 text-sm font-bold">
                    1
                  </div>
                  <div className="flex-1">
                    <p className="text-gray-900 font-medium">
                      Tap the <span className="inline-flex items-center gap-1">
                        <Share className="w-4 h-4 inline text-blue-600" />
                        <span className="font-bold text-blue-600">Share</span>
                      </span> button below
                    </p>
                    <p className="text-sm text-gray-600 mt-1">
                      (At the bottom or top of Safari)
                    </p>
                  </div>
                </div>

                {/* Step 2 */}
                <div className="flex items-start gap-3">
                  <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center flex-shrink-0 text-sm font-bold">
                    2
                  </div>
                  <div className="flex-1">
                    <p className="text-gray-900 font-medium">
                      Select "Add to Home Screen"
                    </p>
                    <p className="text-sm text-gray-600 mt-1">
                      Scroll down if you don't see it
                    </p>
                  </div>
                </div>

                {/* Step 3 */}
                <div className="flex items-start gap-3">
                  <div className="w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center flex-shrink-0 text-sm font-bold">
                    3
                  </div>
                  <div className="flex-1">
                    <p className="text-gray-900 font-medium">
                      Tap "Add" to confirm
                    </p>
                    <p className="text-sm text-gray-600 mt-1">
                      CipherBank will appear on your home screen
                    </p>
                  </div>
                </div>
              </div>

              {/* Benefits */}
              <div className="bg-gradient-to-r from-emerald-50 to-blue-50 border border-emerald-200 rounded-xl p-4">
                <p className="text-sm font-semibold text-gray-900 mb-2">✨ Benefits:</p>
                <ul className="text-sm text-gray-700 space-y-1">
                  <li>• Full-screen experience</li>
                  <li>• Faster access from home screen</li>
                  <li>• Works offline</li>
                  <li>• App-like navigation</li>
                </ul>
              </div>
            </div>

            {/* Actions */}
            <div className="flex gap-3">
              <button
                onClick={handleDismiss}
                className="flex-1 px-4 py-3 bg-gray-100 text-gray-700 rounded-xl font-semibold hover:bg-gray-200 transition-colors"
              >
                Maybe Later
              </button>
              <button
                onClick={handleNeverShow}
                className="px-4 py-3 text-gray-500 text-sm font-medium hover:text-gray-700 transition-colors"
              >
                Don't Show Again
              </button>
            </div>
          </div>

          {/* Animated Share Icon Pointer */}
          <div className="absolute -bottom-8 left-1/2 transform -translate-x-1/2 animate-bounce">
            <div className="bg-blue-600 text-white p-2 rounded-full shadow-lg">
              <ChevronUp className="w-6 h-6" />
            </div>
          </div>
        </div>
      </div>

      {/* Animations */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        @keyframes slideUp {
          from {
            transform: translateY(100%);
            opacity: 0;
          }
          to {
            transform: translateY(0);
            opacity: 1;
          }
        }

        .animate-fadeIn {
          animation: fadeIn 0.3s ease-out;
        }

        .animate-slideUp {
          animation: slideUp 0.4s ease-out;
        }
      `}</style>
    </>
  );
};

export default IOSInstallPrompt;