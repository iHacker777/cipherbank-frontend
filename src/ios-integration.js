/**
 * iOS PWA Enhancements for App.js
 *
 * This file contains the code additions needed to integrate iOS PWA features
 * into your existing App.js file.
 *
 * INTEGRATION INSTRUCTIONS:
 * 1. Add the imports at the top of your App.js
 * 2. Add the useEffect hooks inside your CipherBankUI component
 * 3. Add the IOSInstallPrompt component to your render
 */

// ==================== STEP 1: ADD THESE IMPORTS ====================
// Add these to the top of your App.js file, after your existing imports

import IOSInstallPrompt from './components/IOSInstallPrompt';
import './ios-styles.css';

// ==================== STEP 2: ADD THESE HOOKS ====================
// Add these useEffect hooks inside your CipherBankUI component
// Place them after your existing useEffect hooks

/**
 * iOS Detection and Setup
 * Detects iOS device and sets up iOS-specific features
 */
useEffect(() => {
  // Detect iOS
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
  const isStandalone = window.navigator.standalone ||
                      window.matchMedia('(display-mode: standalone)').matches;

  if (isIOS) {
    // Add iOS class to html element
    document.documentElement.classList.add('ios-device');

    if (isStandalone) {
      document.documentElement.classList.add('ios-standalone');
      console.log('📱 Running in iOS standalone mode');
    }

    // Set up dynamic viewport height for iOS
    const setVH = () => {
      const vh = window.innerHeight * 0.01;
      document.documentElement.style.setProperty('--vh', `${vh}px`);
    };

    // Set initial value
    setVH();

    // Update on resize (keyboard show/hide)
    window.addEventListener('resize', setVH);
    window.addEventListener('orientationchange', setVH);

    return () => {
      window.removeEventListener('resize', setVH);
      window.removeEventListener('orientationchange', setVH);
    };
  }
}, []);

/**
 * Prevent iOS Pull-to-Refresh
 * Prevents the pull-to-refresh gesture on iOS Safari
 */
useEffect(() => {
  let lastY = 0;

  const preventPullToRefresh = (e) => {
    const scrollY = window.pageYOffset || document.documentElement.scrollTop;
    const direction = e.touches[0].clientY - lastY;

    // Prevent pull-to-refresh when at top of page and pulling down
    if (scrollY === 0 && direction > 0) {
      e.preventDefault();
    }

    lastY = e.touches[0].clientY;
  };

  document.addEventListener('touchstart', (e) => {
    lastY = e.touches[0].clientY;
  }, { passive: false });

  document.addEventListener('touchmove', preventPullToRefresh, { passive: false });

  return () => {
    document.removeEventListener('touchmove', preventPullToRefresh);
  };
}, []);

/**
 * Haptic Feedback for iOS
 * Provides haptic feedback on button clicks (iOS 10+)
 */
const triggerHapticFeedback = (type = 'light') => {
  if (window.navigator && window.navigator.vibrate) {
    const patterns = {
      light: [10],
      medium: [20],
      heavy: [30],
      success: [10, 50, 10],
      warning: [20, 100, 20],
      error: [30, 100, 30]
    };

    window.navigator.vibrate(patterns[type] || patterns.light);
  }
};

/**
 * iOS Safe Area CSS Variables
 * Adds CSS variables for safe area insets
 */
useEffect(() => {
  // Check if safe area insets are supported
  const supportsSafeArea = CSS.supports('padding-top: env(safe-area-inset-top)');

  if (supportsSafeArea) {
    document.documentElement.style.setProperty(
      '--safe-area-inset-top',
      'env(safe-area-inset-top)'
    );
    document.documentElement.style.setProperty(
      '--safe-area-inset-right',
      'env(safe-area-inset-right)'
    );
    document.documentElement.style.setProperty(
      '--safe-area-inset-bottom',
      'env(safe-area-inset-bottom)'
    );
    document.documentElement.style.setProperty(
      '--safe-area-inset-left',
      'env(safe-area-inset-left)'
    );
  }
}, []);

/**
 * iOS Keyboard Handling
 * Adjusts viewport when keyboard appears
 */
useEffect(() => {
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);

  if (!isIOS) return;

  let initialViewportHeight = window.visualViewport?.height || window.innerHeight;

  const handleViewportChange = () => {
    const currentViewportHeight = window.visualViewport?.height || window.innerHeight;
    const viewportHeightDiff = initialViewportHeight - currentViewportHeight;

    // Keyboard is visible if viewport height decreased significantly
    if (viewportHeightDiff > 150) {
      document.body.classList.add('keyboard-visible');
    } else {
      document.body.classList.remove('keyboard-visible');
    }
  };

  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', handleViewportChange);

    return () => {
      window.visualViewport.removeEventListener('resize', handleViewportChange);
    };
  }
}, []);

/**
 * Prevent iOS Zoom on Input Focus
 * Already handled in CSS, but this adds programmatic prevention
 */
useEffect(() => {
  const preventZoom = (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
      // Ensure font size is at least 16px to prevent zoom
      const fontSize = window.getComputedStyle(e.target).fontSize;
      if (parseInt(fontSize) < 16) {
        e.target.style.fontSize = '16px';
      }
    }
  };

  document.addEventListener('focus', preventZoom, true);

  return () => {
    document.removeEventListener('focus', preventZoom, true);
  };
}, []);

// ==================== STEP 3: UPDATE YOUR BUTTON CLICKS ====================
// Add haptic feedback to your button onClick handlers
// Example for login button:

const handleSubmitWithHaptic = async (e) => {
  e.preventDefault();
  triggerHapticFeedback('light'); // Add this line
  // ... rest of your existing handleSubmit code
  await handleSubmit(e);
};

// Example for successful actions:
const onSuccessWithHaptic = () => {
  triggerHapticFeedback('success'); // Add this line
  showNotification('Success!', 'success');
};

// Example for errors:
const onErrorWithHaptic = () => {
  triggerHapticFeedback('error'); // Add this line
  showNotification('Error!', 'error');
};

// ==================== STEP 4: ADD TO RENDER ====================
// Add the IOSInstallPrompt component to your render method
// Place it inside your main return statement, after ErrorBoundary

return (
  <ErrorBoundary>
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Add this component */}
      <IOSInstallPrompt />

      {/* ... rest of your existing JSX */}
    </div>
  </ErrorBoundary>
);

// ==================== STEP 5: UPDATE YOUR STYLES ====================
// Update your inline styles to support iOS safe areas

// Example: Update notification positioning
{notification && (
  <div
    className="fixed top-4 right-4 z-50 animate-slideInRight"
    style={{
      top: 'calc(var(--safe-area-inset-top, 0px) + 1rem)'
    }}
  >
    {/* ... notification content */}
  </div>
)}

// Example: Update token expiry indicator positioning
{token && tokenExpiry && currentView !== 'login' && (
  <div
    className="fixed bottom-4 right-4 z-40"
    style={{
      bottom: 'calc(var(--safe-area-inset-bottom, 0px) + 1rem)'
    }}
  >
    {/* ... expiry indicator content */}
  </div>
)}

// ==================== STEP 6: UPDATE SIDEBAR ====================
// Add safe area padding to sidebar

const Sidebar = ({ ... }) => {
  return (
    <aside
      className={`fixed top-0 left-0 h-full w-72 bg-gradient-to-b from-slate-900 to-slate-800 text-white p-6 z-50 transition-transform duration-300 ${...}`}
      style={{
        paddingTop: 'calc(var(--safe-area-inset-top, 0px) + 1.5rem)',
        paddingLeft: 'calc(var(--safe-area-inset-left, 0px) + 1.5rem)',
        paddingBottom: 'calc(var(--safe-area-inset-bottom, 0px) + 1.5rem)'
      }}
    >
      {/* ... sidebar content */}
    </aside>
  );
};

// ==================== ADDITIONAL HELPER FUNCTIONS ====================

/**
 * Check if running in iOS standalone mode
 */
const isIOSStandalone = () => {
  return window.navigator.standalone ||
         window.matchMedia('(display-mode: standalone)').matches;
};

/**
 * Check if device is iOS
 */
const isIOSDevice = () => {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
};

/**
 * Get iOS version
 */
const getIOSVersion = () => {
  const match = navigator.userAgent.match(/OS (\d+)_(\d+)_?(\d+)?/);
  if (match) {
    return {
      major: parseInt(match[1], 10),
      minor: parseInt(match[2], 10),
      patch: parseInt(match[3] || 0, 10)
    };
  }
  return null;
};

/**
 * Detect iPhone model (approximate)
 */
const getIPhoneModel = () => {
  const width = window.screen.width;
  const height = window.screen.height;
  const ratio = window.devicePixelRatio;

  // iPhone 17 Pro Max / 16 Pro Max / 15 Pro Max
  if ((width === 430 || height === 430) && ratio === 3) {
    return 'iPhone Pro Max';
  }

  // iPhone 17 Pro / 16 Pro / 15 Pro
  if ((width === 393 || height === 393) && ratio === 3) {
    return 'iPhone Pro';
  }

  // iPhone 17 / 16 / 15
  if ((width === 390 || height === 390) && ratio === 3) {
    return 'iPhone';
  }

  // iPhone SE
  if ((width === 375 || height === 375) && ratio === 2) {
    return 'iPhone SE';
  }

  return 'Unknown iPhone';
};

/**
 * Share functionality using iOS native share
 */
const shareContent = async (title, text, url) => {
  if (navigator.share) {
    try {
      await navigator.share({
        title: title,
        text: text,
        url: url
      });
      triggerHapticFeedback('success');
      return true;
    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('Error sharing:', error);
        triggerHapticFeedback('error');
      }
      return false;
    }
  } else {
    // Fallback for browsers that don't support Web Share API
    if (navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(url);
        showNotification('Link copied to clipboard!', 'success');
        triggerHapticFeedback('success');
        return true;
      } catch (error) {
        console.error('Error copying to clipboard:', error);
        return false;
      }
    }
  }
  return false;
};

// Export helper functions if needed
export {
  triggerHapticFeedback,
  isIOSStandalone,
  isIOSDevice,
  getIOSVersion,
  getIPhoneModel,
  shareContent
};