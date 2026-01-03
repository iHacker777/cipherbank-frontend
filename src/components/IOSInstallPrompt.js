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
    const userAgent = window.navigator.userAgent.toLowerCase();
    const iOS = /iphone|ipad|ipod/.test(userAgent);
    setIsIOS(iOS);

    const standalone = window.navigator.standalone ||
                      window.matchMedia('(display-mode: standalone)').matches;
    setIsStandalone(standalone);

    const safari = /safari/.test(userAgent) && !/chrome|crios|fxios/.test(userAgent);
    setIsSafari(safari);

    const dismissed = localStorage.getItem('ios-pwa-prompt-dismissed');
    const dismissedTime = dismissed ? parseInt(dismissed, 10) : 0;
    const daysSinceDismissed = (Date.now() - dismissedTime) / (1000 * 60 * 60 * 24);

    if (iOS && !standalone && safari && (!dismissed || daysSinceDismissed > 7)) {
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
    localStorage.setItem('ios-pwa-prompt-dismissed', '9999999999999');
  };

  if (!showPrompt || !isIOS || isStandalone || !isSafari) {
    return null;
  }

  return (
    <>
      <div className="install-prompt-overlay" onClick={handleDismiss} />

      <div className="install-prompt">
        <button onClick={handleDismiss} className="install-prompt-close" aria-label="Close">
          <X className="w-5 h-5" />
        </button>

        <div className="install-prompt-content">
          <div className="install-prompt-header">
            <div className="install-prompt-icon">
              <Smartphone className="w-7 h-7 text-white" />
            </div>
            <div>
              <h3 className="install-prompt-title">Install CipherBank</h3>
              <p className="install-prompt-subtitle">Add to your home screen</p>
            </div>
          </div>

          <div className="install-prompt-steps">
            <p className="install-prompt-instruction">Install this app for the best experience:</p>

            <div className="install-step">
              <div className="step-number">1</div>
              <div className="step-content">
                <p className="step-title">
                  Tap the <Share className="w-4 h-4 inline" /> <strong>Share</strong> button
                </p>
                <p className="step-hint">At the bottom of Safari</p>
              </div>
            </div>

            <div className="install-step">
              <div className="step-number">2</div>
              <div className="step-content">
                <p className="step-title">Select "Add to Home Screen"</p>
                <p className="step-hint">Scroll down if you don't see it</p>
              </div>
            </div>

            <div className="install-step">
              <div className="step-number">3</div>
              <div className="step-content">
                <p className="step-title">Tap "Add" to confirm</p>
                <p className="step-hint">CipherBank will appear on your home screen</p>
              </div>
            </div>
          </div>

          <div className="install-prompt-actions">
            <button onClick={handleDismiss} className="lg-btn lg-btn-secondary">
              Maybe Later
            </button>
            <button onClick={handleNeverShow} className="install-prompt-never">
              Don't Show Again
            </button>
          </div>
        </div>

        <div className="install-prompt-arrow">
          <ChevronUp className="w-6 h-6" />
        </div>
      </div>

      <style>{`
        .install-prompt-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.5);
          backdrop-filter: blur(4px);
          z-index: 9998;
          animation: fadeIn 0.3s ease-out;
        }

        .install-prompt {
          position: fixed;
          bottom: 0;
          left: 0;
          right: 0;
          z-index: 9999;
          background: var(--bg-primary, #FFFFFF);
          border-radius: 24px 24px 0 0;
          padding: 24px;
          padding-bottom: calc(24px + env(safe-area-inset-bottom, 0px));
          box-shadow: 0 -10px 40px rgba(0, 0, 0, 0.2);
          animation: slideUp 0.4s ease-out;
        }

        @keyframes slideUp {
          from { transform: translateY(100%); }
          to { transform: translateY(0); }
        }

        .install-prompt-close {
          position: absolute;
          top: 16px;
          right: 16px;
          background: var(--fill-secondary, rgba(120, 120, 128, 0.16));
          border: none;
          border-radius: 50%;
          width: 32px;
          height: 32px;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          color: var(--label-secondary, #8E8E93);
        }

        .install-prompt-content {
          padding-right: 32px;
        }

        .install-prompt-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 20px;
        }

        .install-prompt-icon {
          width: 56px;
          height: 56px;
          background: linear-gradient(135deg, #007AFF 0%, #5856D6 100%);
          border-radius: 16px;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 4px 12px rgba(0, 122, 255, 0.3);
        }

        .install-prompt-title {
          font-size: 20px;
          font-weight: 700;
          color: var(--label-primary, #000000);
          margin: 0;
        }

        .install-prompt-subtitle {
          font-size: 14px;
          color: var(--label-secondary, #8E8E93);
          margin: 4px 0 0 0;
        }

        .install-prompt-steps {
          background: var(--fill-quaternary, rgba(116, 116, 128, 0.08));
          border-radius: 16px;
          padding: 16px;
          margin-bottom: 20px;
        }

        .install-prompt-instruction {
          font-size: 15px;
          font-weight: 600;
          color: var(--label-primary, #000000);
          margin: 0 0 16px 0;
        }

        .install-step {
          display: flex;
          gap: 12px;
          margin-bottom: 12px;
        }

        .install-step:last-child {
          margin-bottom: 0;
        }

        .step-number {
          width: 24px;
          height: 24px;
          background: var(--system-blue, #007AFF);
          color: #FFFFFF;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 13px;
          font-weight: 700;
          flex-shrink: 0;
        }

        .step-content {
          flex: 1;
        }

        .step-title {
          font-size: 15px;
          font-weight: 500;
          color: var(--label-primary, #000000);
          margin: 0;
        }

        .step-hint {
          font-size: 13px;
          color: var(--label-secondary, #8E8E93);
          margin: 4px 0 0 0;
        }

        .install-prompt-actions {
          display: flex;
          gap: 12px;
          align-items: center;
        }

        .install-prompt-actions .lg-btn {
          flex: 1;
        }

        .install-prompt-never {
          background: transparent;
          border: none;
          color: var(--label-tertiary, #C7C7CC);
          font-size: 14px;
          cursor: pointer;
          padding: 12px;
        }

        .install-prompt-arrow {
          position: absolute;
          bottom: -32px;
          left: 50%;
          transform: translateX(-50%);
          background: var(--system-blue, #007AFF);
          color: #FFFFFF;
          width: 40px;
          height: 40px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 4px 12px rgba(0, 122, 255, 0.4);
          animation: bounce 1s ease-in-out infinite;
        }

        @keyframes bounce {
          0%, 100% { transform: translateX(-50%) translateY(0); }
          50% { transform: translateX(-50%) translateY(-8px); }
        }

        @media (prefers-color-scheme: dark) {
          .install-prompt {
            background: var(--bg-primary, #1C1C1E);
          }
        }
      `}</style>
    </>
  );
};

export default IOSInstallPrompt;
