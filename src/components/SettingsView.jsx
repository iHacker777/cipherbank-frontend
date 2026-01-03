// ==================== SETTINGS VIEW (iOS 26 STYLE) ====================
// This replaces/enhances ChangePasswordView with full settings including Appearance

import React, { useState, useEffect, useCallback } from 'react';
import { 
  Key, Eye, EyeOff, CheckCircle, XCircle, Sun, Moon, 
  Smartphone, Shield, AlertTriangle, X, ChevronRight,
  Palette, RefreshCw, LogOut, User, Info
} from 'lucide-react';
import haptics from '../utils/ios-haptics';

// ==================== THEME MANAGEMENT HOOK ====================
export const useTheme = () => {
  const [theme, setThemeState] = useState(() => {
    // Get saved theme or default to 'system'
    if (typeof window !== 'undefined') {
      return localStorage.getItem('cipherbank_theme') || 'system';
    }
    return 'system';
  });

  // Apply theme to document
  const applyTheme = useCallback((newTheme) => {
    const root = document.documentElement;
    
    // Remove existing theme attribute
    root.removeAttribute('data-theme');
    
    if (newTheme === 'light') {
      root.setAttribute('data-theme', 'light');
    } else if (newTheme === 'dark') {
      root.setAttribute('data-theme', 'dark');
    }
    // For 'system', we don't set data-theme, letting CSS media queries handle it
    
    // Update meta theme-color for browser chrome
    const metaThemeColor = document.querySelector('meta[name="theme-color"]');
    if (metaThemeColor) {
      if (newTheme === 'dark' || 
          (newTheme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        metaThemeColor.setAttribute('content', '#0A84FF');
      } else {
        metaThemeColor.setAttribute('content', '#007AFF');
      }
    }
  }, []);

  // Set theme and persist
  const setTheme = useCallback((newTheme) => {
    setThemeState(newTheme);
    localStorage.setItem('cipherbank_theme', newTheme);
    applyTheme(newTheme);
    haptics.selection();
  }, [applyTheme]);

  // Initialize theme on mount
  useEffect(() => {
    applyTheme(theme);
    
    // Listen for system theme changes
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => {
      if (theme === 'system') {
        applyTheme('system');
      }
    };
    
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [theme, applyTheme]);

  // Get the actual resolved theme (for display purposes)
  const resolvedTheme = theme === 'system' 
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : theme;

  return { theme, setTheme, resolvedTheme };
};

// ==================== APPEARANCE PICKER COMPONENT ====================
const AppearancePicker = ({ isOpen, onClose, currentTheme, onSelectTheme }) => {
  if (!isOpen) return null;

  const options = [
    { id: 'system', label: 'System', icon: 'system' },
    { id: 'light', label: 'Light', icon: 'light' },
    { id: 'dark', label: 'Dark', icon: 'dark' }
  ];

  return (
    <div className="appearance-picker">
      <div 
        className="appearance-picker-backdrop" 
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="appearance-picker-content" role="dialog" aria-modal="true" aria-labelledby="appearance-title">
        <div className="appearance-picker-header">
          <h2 id="appearance-title" className="appearance-picker-title">Appearance</h2>
          <button 
            className="appearance-picker-close"
            onClick={onClose}
            aria-label="Close"
            type="button"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="appearance-picker-options">
          {options.map(({ id, label, icon }) => (
            <button
              key={id}
              onClick={() => {
                onSelectTheme(id);
                onClose();
              }}
              className={`appearance-option ${currentTheme === id ? 'selected' : ''}`}
              type="button"
              aria-pressed={currentTheme === id}
            >
              <div className={`appearance-option-icon ${icon}`}>
                {icon === 'light' && <Sun className="w-6 h-6" />}
                {icon === 'dark' && <Moon className="w-6 h-6" />}
                {icon === 'system' && <Smartphone className="w-6 h-6" />}
              </div>
              <span className="appearance-option-label">{label}</span>
              {currentTheme === id && (
                <CheckCircle className="w-5 h-5" style={{ color: 'var(--system-blue)' }} />
              )}
            </button>
          ))}
        </div>
        <div style={{ 
          padding: 'var(--space-4, 16px)', 
          paddingTop: 0,
          fontSize: '13px',
          color: 'var(--label-secondary)',
          textAlign: 'center'
        }}>
          {currentTheme === 'system' 
            ? 'Appearance will match your device settings'
            : `${currentTheme.charAt(0).toUpperCase() + currentTheme.slice(1)} mode is always on`
          }
        </div>
      </div>
    </div>
  );
};

// ==================== iOS TOGGLE COMPONENT ====================
const IOSToggle = ({ active, onToggle, disabled = false }) => {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={active}
      disabled={disabled}
      className={`ios-toggle ${active ? 'active' : ''}`}
      onClick={() => {
        haptics.selection();
        onToggle(!active);
      }}
    >
      <span className="ios-toggle-thumb" />
    </button>
  );
};

// ==================== MAIN SETTINGS VIEW ====================
const SettingsView = ({ 
  token, 
  user, 
  showNotification, 
  setCurrentView, 
  setUser, 
  setToken, 
  setTokenExpiry, 
  checkAndRefreshToken,
  autoRefreshEnabled,
  setAutoRefreshEnabled,
  handleLogout,
  credentialsRef
}) => {
  // Theme state
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [showAppearancePicker, setShowAppearancePicker] = useState(false);
  
  // Password change state
  const [passwordData, setPasswordData] = useState({ 
    currentPassword: '', 
    newPassword: '', 
    confirmNewPassword: '' 
  });
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [changing, setChanging] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);
  
  // Haptics state
  const [hapticsEnabled, setHapticsEnabled] = useState(() => {
    const saved = localStorage.getItem('cipherbank_haptics');
    return saved !== 'false'; // Default to true
  });

  // API URL
  const API_AUTH_URL = process.env.REACT_APP_API_AUTH_URL || 'https://testing.thepaytrix.com/api';
  const CONFIG = { PASSWORD_MIN_LENGTH: 6 };

  // Toggle haptics
  const toggleHaptics = (enabled) => {
    setHapticsEnabled(enabled);
    localStorage.setItem('cipherbank_haptics', enabled.toString());
    if (enabled) {
      haptics.enable();
      haptics.success();
    } else {
      haptics.disable();
    }
  };

  // Toggle auto-refresh
  const toggleAutoRefresh = () => {
    if (autoRefreshEnabled) {
      setAutoRefreshEnabled(false);
      if (credentialsRef) credentialsRef.current = null;
      localStorage.removeItem('cipherbank_credentials');
      showNotification('Auto-refresh disabled', 'info');
    } else {
      showNotification('Please re-login to enable auto-refresh', 'info');
    }
    haptics.selection();
  };

  // Password strength calculation
  const calculatePasswordStrength = (password) => {
    let strength = 0;
    if (password.length >= 8) strength += 25;
    if (password.length >= 12) strength += 15;
    if (/[a-z]/.test(password)) strength += 15;
    if (/[A-Z]/.test(password)) strength += 15;
    if (/[0-9]/.test(password)) strength += 15;
    if (/[^a-zA-Z0-9]/.test(password)) strength += 15;
    return Math.min(strength, 100);
  };

  useEffect(() => {
    setPasswordStrength(calculatePasswordStrength(passwordData.newPassword));
  }, [passwordData.newPassword]);

  // Handle password change
  const handleChangePassword = async (e) => {
    e.preventDefault();
    haptics.medium();

    if (!passwordData.currentPassword) {
      showNotification('Enter current password', 'error');
      haptics.error();
      return;
    }
    if (passwordData.newPassword.length < CONFIG.PASSWORD_MIN_LENGTH) {
      showNotification(`New password must be at least ${CONFIG.PASSWORD_MIN_LENGTH} characters`, 'error');
      haptics.error();
      return;
    }
    if (passwordData.newPassword !== passwordData.confirmNewPassword) {
      showNotification('Passwords do not match', 'error');
      haptics.error();
      return;
    }
    if (passwordStrength < 40) {
      showNotification('Password is too weak', 'error');
      haptics.error();
      return;
    }
    if (passwordData.currentPassword === passwordData.newPassword) {
      showNotification('New password must be different', 'error');
      haptics.error();
      return;
    }

    const tokenValid = await checkAndRefreshToken();
    if (!tokenValid) return;

    setChanging(true);

    try {
      const response = await fetch(`${API_AUTH_URL}/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (response.ok) {
        haptics.success();
        showNotification('Password changed successfully!', 'success');
        setPasswordData({ currentPassword: '', newPassword: '', confirmNewPassword: '' });
      } else if (response.status === 401) {
        haptics.error();
        localStorage.removeItem('cipherbank_token');
        localStorage.removeItem('cipherbank_user');
        localStorage.removeItem('cipherbank_token_expiry');
        setToken(null);
        setUser(null);
        setTokenExpiry(null);
        setCurrentView('login');
        showNotification('Session expired. Please login again.', 'error');
      } else {
        haptics.error();
        showNotification(data.message || 'Failed to change password', 'error');
      }
    } catch (error) {
      haptics.error();
      showNotification('Network error. Please try again.', 'error');
    } finally {
      setChanging(false);
    }
  };

  const getStrengthClass = (strength) => {
    if (strength < 40) return 'weak';
    if (strength < 70) return 'medium';
    return 'strong';
  };

  const getStrengthText = (strength) => {
    if (strength < 40) return 'Weak';
    if (strength < 70) return 'Medium';
    return 'Strong';
  };

  const getThemeLabel = () => {
    switch (theme) {
      case 'light': return 'Light';
      case 'dark': return 'Dark';
      default: return 'System';
    }
  };

  return (
    <div className="settings-view" style={{ padding: 'var(--space-4, 16px)' }}>
      {/* User Info Banner */}
      <div className="user-info-banner" style={{ marginBottom: 'var(--space-6, 24px)' }}>
        <div className="user-avatar">
          <User className="w-5 h-5" />
        </div>
        <div>
          <p className="user-label">Signed in as</p>
          <p className="user-name">{user?.name || user?.username || 'User'}</p>
        </div>
      </div>

      {/* Appearance Section */}
      <div className="settings-section">
        <div className="settings-section-title">Appearance</div>
        <div className="settings-group">
          <button
            type="button"
            className="settings-item"
            onClick={() => {
              haptics.light();
              setShowAppearancePicker(true);
            }}
          >
            <div className="settings-item-left">
              <div className="settings-item-icon purple">
                <Palette className="w-5 h-5" />
              </div>
              <div className="settings-item-content">
                <div className="settings-item-title">Theme</div>
                <div className="settings-item-subtitle">
                  {theme === 'system' 
                    ? `System (${resolvedTheme === 'dark' ? 'Dark' : 'Light'})` 
                    : getThemeLabel()}
                </div>
              </div>
            </div>
            <div className="settings-item-right">
              <span className="settings-item-value">{getThemeLabel()}</span>
              <ChevronRight className="w-5 h-5 settings-item-chevron" />
            </div>
          </button>
          
          <div className="settings-item">
            <div className="settings-item-left">
              <div className="settings-item-icon orange">
                <Smartphone className="w-5 h-5" />
              </div>
              <div className="settings-item-content">
                <div className="settings-item-title">Haptic Feedback</div>
                <div className="settings-item-subtitle">Vibration on interactions</div>
              </div>
            </div>
            <div className="settings-item-right">
              <IOSToggle 
                active={hapticsEnabled} 
                onToggle={toggleHaptics}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Session Section */}
      <div className="settings-section">
        <div className="settings-section-title">Session</div>
        <div className="settings-group">
          <div className="settings-item">
            <div className="settings-item-left">
              <div className="settings-item-icon green">
                <RefreshCw className="w-5 h-5" />
              </div>
              <div className="settings-item-content">
                <div className="settings-item-title">Auto-Refresh Token</div>
                <div className="settings-item-subtitle">Stay signed in automatically</div>
              </div>
            </div>
            <div className="settings-item-right">
              <IOSToggle 
                active={autoRefreshEnabled} 
                onToggle={toggleAutoRefresh}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Security Section - Password Change */}
      <div className="settings-section">
        <div className="settings-section-title">Security</div>
        <div className="settings-group" style={{ padding: 'var(--space-5, 20px)' }}>
          <form onSubmit={handleChangePassword} className="password-form">
            {/* Current Password */}
            <div className="form-group">
              <label className="form-label">Current Password</label>
              <div className="input-wrapper">
                <div className="input-icon"><Key className="w-5 h-5" /></div>
                <input
                  type={showCurrentPassword ? 'text' : 'password'}
                  value={passwordData.currentPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                  placeholder="Enter current password"
                  className="lg-input"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => {
                    haptics.light();
                    setShowCurrentPassword(!showCurrentPassword);
                  }}
                  className="input-action"
                  aria-label={showCurrentPassword ? 'Hide password' : 'Show password'}
                >
                  {showCurrentPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* New Password */}
            <div className="form-group">
              <label className="form-label">New Password</label>
              <div className="input-wrapper">
                <div className="input-icon"><Shield className="w-5 h-5" /></div>
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  value={passwordData.newPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                  placeholder="Enter new password"
                  className="lg-input"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => {
                    haptics.light();
                    setShowNewPassword(!showNewPassword);
                  }}
                  className="input-action"
                  aria-label={showNewPassword ? 'Hide password' : 'Show password'}
                >
                  {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              
              {/* Password Strength */}
              {passwordData.newPassword && (
                <div className="password-strength">
                  <div className="strength-bar">
                    <div 
                      className={`strength-fill ${getStrengthClass(passwordStrength)}`}
                      style={{ width: `${passwordStrength}%` }}
                    />
                  </div>
                  <span className={`strength-text ${getStrengthClass(passwordStrength)}`}>
                    {getStrengthText(passwordStrength)}
                  </span>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div className="form-group">
              <label className="form-label">Confirm New Password</label>
              <div className="input-wrapper">
                <div className="input-icon"><Shield className="w-5 h-5" /></div>
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={passwordData.confirmNewPassword}
                  onChange={(e) => setPasswordData({ ...passwordData, confirmNewPassword: e.target.value })}
                  placeholder="Confirm new password"
                  className="lg-input"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => {
                    haptics.light();
                    setShowConfirmPassword(!showConfirmPassword);
                  }}
                  className="input-action"
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              
              {/* Password Match Indicator */}
              {passwordData.confirmNewPassword && (
                <div className={`password-match ${passwordData.newPassword === passwordData.confirmNewPassword ? 'match' : 'no-match'}`}>
                  {passwordData.newPassword === passwordData.confirmNewPassword 
                    ? <><CheckCircle className="w-4 h-4" /> Passwords match</> 
                    : <><XCircle className="w-4 h-4" /> Passwords don't match</>
                  }
                </div>
              )}
            </div>

            {/* Submit Button */}
            <button 
              type="submit" 
              disabled={changing || passwordStrength < 40} 
              className={`lg-btn lg-btn-primary w-full ${changing || passwordStrength < 40 ? 'disabled' : ''}`}
            >
              {changing ? (
                <>
                  <span className="spinner"></span> Changing Password...
                </>
              ) : 'Change Password'}
            </button>
          </form>

          {/* Security Tips */}
          <div className="security-tips">
            <AlertTriangle className="tips-icon" />
            <div>
              <div className="tips-title">Security Tips</div>
              <ul className="tips-list">
                <li>• Use a unique password for each account</li>
                <li>• Include letters, numbers & symbols</li>
                <li>• Avoid personal information</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* About Section */}
      <div className="settings-section">
        <div className="settings-section-title">About</div>
        <div className="settings-group">
          <div className="settings-item">
            <div className="settings-item-left">
              <div className="settings-item-icon gray">
                <Info className="w-5 h-5" />
              </div>
              <div className="settings-item-content">
                <div className="settings-item-title">CipherBank</div>
                <div className="settings-item-subtitle">Version 3.0.0</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Sign Out Button */}
      <div className="settings-section" style={{ marginTop: 'var(--space-8, 32px)' }}>
        <button
          type="button"
          onClick={() => {
            haptics.medium();
            handleLogout();
          }}
          className="lg-btn w-full"
          style={{
            background: 'rgba(255, 59, 48, 0.1)',
            color: 'var(--system-red, #FF3B30)',
            border: 'none'
          }}
        >
          <LogOut className="w-5 h-5" />
          Sign Out
        </button>
      </div>

      {/* Appearance Picker Modal */}
      <AppearancePicker
        isOpen={showAppearancePicker}
        onClose={() => setShowAppearancePicker(false)}
        currentTheme={theme}
        onSelectTheme={setTheme}
      />
    </div>
  );
};

export default SettingsView;
export { useTheme, AppearancePicker, IOSToggle };
