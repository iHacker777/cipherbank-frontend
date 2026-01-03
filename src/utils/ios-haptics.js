/**
 * iOS Haptics Utility for Web
 *
 * Provides haptic feedback on iOS Safari 17.4+ using the switch checkbox method,
 * with fallback to Vibration API for Android devices.
 *
 * The switch checkbox method is currently the ONLY way to trigger system haptics
 * in iOS Safari - navigator.vibrate() is NOT supported on iOS.
 */

class IOSHaptics {
  constructor() {
    this._enabled = true;
    this._isIOS = false;
    this._isSupported = false;
    this._container = null;

    this._init();
  }

  _init() {
    // Check if we're in a browser environment
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    // Detect iOS
    this._isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;

    // Check for iOS 17.4+ (required for switch haptics)
    if (this._isIOS) {
      const match = navigator.userAgent.match(/OS (\d+)_(\d+)/);
      if (match) {
        const major = parseInt(match[1], 10);
        const minor = parseInt(match[2], 10);
        // iOS 17.4 or later supports switch haptics
        this._isSupported = major > 17 || (major === 17 && minor >= 4);
      }
    }

    // Android fallback - check for Vibration API
    if (!this._isIOS && 'vibrate' in navigator) {
      this._isSupported = true;
    }

    // Create hidden container for haptic elements
    if (this._isIOS && this._isSupported) {
      this._createContainer();
    }

    // Load saved preference
    const saved = localStorage.getItem('cipherbank_haptics');
    if (saved === 'false') {
      this._enabled = false;
    }

    console.log(`🎯 Haptics initialized: iOS=${this._isIOS}, Supported=${this._isSupported}`);
  }

  _createContainer() {
    if (this._container) return;

    this._container = document.createElement('div');
    this._container.id = 'haptic-container';
    this._container.setAttribute('aria-hidden', 'true');
    this._container.style.cssText = `
      position: fixed;
      top: -9999px;
      left: -9999px;
      width: 1px;
      height: 1px;
      overflow: hidden;
      pointer-events: none;
      opacity: 0;
    `;

    // Append when DOM is ready
    if (document.body) {
      document.body.appendChild(this._container);
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        document.body.appendChild(this._container);
      });
    }
  }

  /**
   * Trigger haptic feedback using iOS switch checkbox method
   * This is the ONLY method that works on iOS Safari 17.4+
   */
  _triggerIOSHaptic() {
    if (!this._enabled || !this._isSupported || !this._container) return;

    try {
      // Create a switch checkbox - this is what triggers the iOS system haptic
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.setAttribute('switch', ''); // Critical: the 'switch' attribute triggers haptics
      checkbox.style.cssText = `
        position: absolute;
        opacity: 0;
        pointer-events: none;
      `;

      this._container.appendChild(checkbox);

      // Use requestAnimationFrame for proper timing with iOS render cycle
      requestAnimationFrame(() => {
        checkbox.click(); // This triggers the system haptic

        // Clean up after a short delay
        requestAnimationFrame(() => {
          if (checkbox.parentNode) {
            checkbox.parentNode.removeChild(checkbox);
          }
        });
      });
    } catch (error) {
      console.warn('Haptic feedback failed:', error);
    }
  }

  /**
   * Trigger haptic feedback using Vibration API (Android)
   */
  _triggerVibration(pattern = [10]) {
    if (!this._enabled) return;

    try {
      if ('vibrate' in navigator) {
        navigator.vibrate(pattern);
      }
    } catch (error) {
      console.warn('Vibration failed:', error);
    }
  }

  /**
   * Trigger haptic feedback
   */
  trigger() {
    if (!this._enabled || !this._isSupported) return;

    if (this._isIOS) {
      this._triggerIOSHaptic();
    } else {
      this._triggerVibration([10]);
    }
  }

  // Convenience methods for different feedback intensities

  /** Light feedback - for selections, toggles */
  light() {
    this.trigger();
  }

  /** Medium feedback - for confirmations */
  medium() {
    if (this._isIOS) {
      this.trigger();
    } else {
      this._triggerVibration([15]);
    }
  }

  /** Heavy/strong feedback - for important actions */
  heavy() {
    if (this._isIOS) {
      this.trigger();
    } else {
      this._triggerVibration([25]);
    }
  }

  /** Success feedback */
  success() {
    if (this._isIOS) {
      this.trigger();
    } else {
      this._triggerVibration([10, 50, 10]);
    }
  }

  /** Warning feedback */
  warning() {
    if (this._isIOS) {
      this.trigger();
      setTimeout(() => this.trigger(), 100);
    } else {
      this._triggerVibration([20, 100, 20]);
    }
  }

  /** Error feedback */
  error() {
    if (this._isIOS) {
      this.trigger();
      setTimeout(() => this.trigger(), 80);
      setTimeout(() => this.trigger(), 160);
    } else {
      this._triggerVibration([30, 50, 30, 50, 30]);
    }
  }

  /** Selection feedback - for picker changes, tab switches */
  selection() {
    this.light();
  }

  // Control methods

  /** Enable haptic feedback */
  enable() {
    this._enabled = true;
    localStorage.setItem('cipherbank_haptics', 'true');
  }

  /** Disable haptic feedback */
  disable() {
    this._enabled = false;
    localStorage.setItem('cipherbank_haptics', 'false');
  }

  /** Toggle haptic feedback */
  toggle() {
    if (this._enabled) {
      this.disable();
    } else {
      this.enable();
    }
    return this._enabled;
  }

  /** Check if haptics are enabled */
  get isEnabled() {
    return this._enabled;
  }

  /** Check if haptics are supported on this device */
  get isSupported() {
    return this._isSupported;
  }

  /** Check if this is an iOS device */
  get isIOS() {
    return this._isIOS;
  }
}

// Create singleton instance
const haptics = new IOSHaptics();

export default haptics;