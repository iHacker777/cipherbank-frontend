import React, { useState, useEffect } from 'react';
import { Upload, FileText, CheckCircle, XCircle, TrendingUp, DollarSign, Activity, LogOut, Menu, X, ChevronRight, Download, Search, Filter, Users, Shield, Eye, EyeOff, Copy, RefreshCw, Key } from 'lucide-react';
// API Base URL - update this to your backend URL
const API_BASE_URL = 'https://cipher.thepaytrix.com/api';
// JWT Token Validation Helper - Simplified for JWE tokens
const isTokenValid = (token) => {
  // For encrypted tokens (JWE), we can't decode them client-side
  // Just check if token exists and has reasonable format
  if (!token || typeof token !== 'string' || token.trim().length === 0) {
    return false;
  }

  // Check if it looks like a token (has dots)
  const parts = token.split('.');
  if (parts.length < 3) {
    console.warn('Invalid token format');
    return false;
  }

  // Token appears valid - let backend validate it
  return true;
};

// Function to clear session and redirect to login
const clearSessionAndRedirect = (setCurrentView, setUser, setToken, showNotification, currentView) => {
  localStorage.removeItem('cipherbank_token');
  localStorage.removeItem('cipherbank_user');
  setToken(null);
  setUser(null);
  setCurrentView('login');
  // Only show notification if we're not already on login page
  if (showNotification && currentView !== 'login') {
    showNotification('Session expired. Please login again.', 'error');
  }
};
// ========== END OF HELPER FUNCTIONS ==========

const CipherBankUI = () => {
  const [currentView, setCurrentView] = useState('login');
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [notification, setNotification] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // Animation state
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);

    // Check for existing session
    const savedToken = localStorage.getItem('cipherbank_token');
    const savedUser = localStorage.getItem('cipherbank_user');

    if (savedToken && savedUser) {
      // Validate token before restoring session
      if (isTokenValid(savedToken)) {
        try {
          const userData = JSON.parse(savedUser);
          setToken(savedToken);
          setUser(userData);
          setCurrentView('dashboard');
          console.log('Session restored successfully');
        } catch (error) {
          console.error('Failed to parse user data:', error);
          // Clear corrupted data
          localStorage.removeItem('cipherbank_token');
          localStorage.removeItem('cipherbank_user');
        }
      } else {
        // Token invalid/expired - clear everything silently
        console.log('Invalid or expired token found, clearing session');
        localStorage.removeItem('cipherbank_token');
        localStorage.removeItem('cipherbank_user');
      }
    } else {
      console.log('No saved session found');
    }
  }, []);

  // Periodic token validation - check every 30 seconds
  //useEffect(() => {
    // Don't run validation if:
    // 1. No token exists
    // 2. On login page
    // 3. Currently loading (during login)
    //if (!token || currentView === 'login') return;

    //const intervalId = setInterval(() => {
      //if (!isTokenValid(token)) {
        //console.log('Token expired during session');
        //clearSessionAndRedirect(setCurrentView, setUser, setToken, showNotification, currentView);
      //}
    //}, 30000);

    //return () => clearInterval(intervalId);
  //}, [token, currentView]);

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('cipherbank_token');
    localStorage.removeItem('cipherbank_user');
    setCurrentView('login');
    showNotification('Logged out successfully', 'info');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Notification Toast */}
      {notification && (
        <div className={`fixed top-4 right-4 z-50 animate-slideInRight`}>
          <div className={`flex items-center gap-3 px-6 py-4 rounded-xl shadow-2xl backdrop-blur-md ${
            notification.type === 'success' ? 'bg-emerald-500' : 
            notification.type === 'error' ? 'bg-red-500' : 'bg-blue-500'
          } text-white`}>
            {notification.type === 'success' && <CheckCircle className="w-5 h-5" />}
            {notification.type === 'error' && <XCircle className="w-5 h-5" />}
            <span className="font-medium">{notification.message}</span>
          </div>
        </div>
      )}

      {/* Main Content */}
      {currentView === 'login' && (
        <LoginView 
          setCurrentView={setCurrentView} 
          setUser={setUser} 
          setToken={setToken}
          showNotification={showNotification}
          setIsLoading={setIsLoading}
        />
      )}
      {(currentView === 'dashboard' || currentView === 'upload' || currentView === 'statements' || currentView === 'users' || currentView === 'changepassword') && (
        <DashboardLayout
          currentView={currentView}
          setCurrentView={setCurrentView}
          user={user}
          token={token}
          setUser={setUser}
          setToken={setToken}
          handleLogout={handleLogout}
          showNotification={showNotification}
          isMenuOpen={isMenuOpen}
          setIsMenuOpen={setIsMenuOpen}
        />
      )}

      {/* Loading Overlay */}
      {isLoading && (
        <div className="fixed inset-0 bg-black/20 backdrop-blur-sm z-50 flex items-center justify-center">
          <div className="bg-white rounded-2xl p-8 shadow-2xl">
            <div className="w-16 h-16 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin mx-auto"></div>
            <p className="mt-4 text-gray-600 font-medium">Processing...</p>
          </div>
        </div>
      )}

      <style>{`
        @keyframes slideInRight {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }

        @keyframes fadeInUp {
          from {
            transform: translateY(20px);
            opacity: 0;
          }
          to {
            transform: translateY(0);
            opacity: 1;
          }
        }

        @keyframes scaleIn {
          from {
            transform: scale(0.95);
            opacity: 0;
          }
          to {
            transform: scale(1);
            opacity: 1;
          }
        }

        @keyframes shimmer {
          0% {
            background-position: -1000px 0;
          }
          100% {
            background-position: 1000px 0;
          }
        }

        .animate-slideInRight {
          animation: slideInRight 0.4s ease-out;
        }

        .animate-fadeInUp {
          animation: fadeInUp 0.6s ease-out;
        }

        .animate-scaleIn {
          animation: scaleIn 0.4s ease-out;
        }

        .animate-shimmer {
          background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
          background-size: 1000px 100%;
          animation: shimmer 2s infinite;
        }

        .hover-lift {
          transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .hover-lift:hover {
          transform: translateY(-4px);
          box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }

        .glass-effect {
          background: rgba(255, 255, 255, 0.9);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(255, 255, 255, 0.5);
        }

        .gradient-text {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }
      `}</style>
    </div>
  );
};

// Login/Register View
const LoginView = ({ setCurrentView, setUser, setToken, showNotification, setIsLoading }) => {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    roleIds: []
  });
const validateForm = () => {
  if (!formData.username || formData.username.trim().length < 3) {
    showNotification('Username must be at least 3 characters long', 'error');
    return false;
  }

  if (!formData.password || formData.password.length < 6) {
    showNotification('Password must be at least 6 characters long', 'error');
    return false;
  }

  return true;
};
  const handleSubmit = async (e) => {
    e.preventDefault();

    // Validate form
    if (!validateForm()) {
      return;
    }

    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      // Try to parse response as JSON
      let data;
      try {
        data = await response.json();
      } catch (jsonError) {
        // If JSON parsing fails, create a default error object
        data = { message: 'Invalid response from server' };
      }

      if (response.ok) {
        // SUCCESS PATH
        if (!data.token) {
          showNotification('No token received from server', 'error');
          return;
        }

        // Set token
        setToken(data.token);
        localStorage.setItem('cipherbank_token', data.token);

        // Use roles from backend response
        const userData = {
          username: data.username || formData.username,
          roles: data.roles || ['ROLE_USER']
        };
        setUser(userData);
        localStorage.setItem('cipherbank_user', JSON.stringify(userData));

        showNotification('Login successful!', 'success');
        setCurrentView('dashboard');
      } else {
        // ERROR PATH - response not OK
        let errorMessage;

        switch (response.status) {
          case 400:
            errorMessage = data.message || 'Invalid request. Please check your input.';
            break;
          case 401:
          case 403:
            errorMessage = 'Invalid username or password. Please try again.';
            break;
          case 404:
            errorMessage = 'Service not found. Please contact support.';
            break;
          case 500:
            errorMessage = 'Server error. Please try again later.';
            break;
          default:
            errorMessage = data.message || `Authentication failed (Error ${response.status})`;
        }

        showNotification(errorMessage, 'error');
      }
    } catch (error) {
      // Network errors or other exceptions
      console.error('Login error:', error);
      showNotification('Connection error. Please check your internet connection and try again.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      {/* Animated Background Circles */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute w-96 h-96 bg-blue-200/30 rounded-full blur-3xl -top-48 -left-48 animate-pulse"></div>
        <div className="absolute w-96 h-96 bg-purple-200/30 rounded-full blur-3xl -bottom-48 -right-48 animate-pulse" style={{animationDelay: '1s'}}></div>
      </div>

      <div className="w-full max-w-md relative animate-fadeInUp">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-2xl shadow-xl mb-4 hover-lift">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-4xl font-bold gradient-text mb-2">Cipher Bank</h1>
          <p className="text-gray-600">Secure & Automated Statement Parsing</p>
        </div>
        {/* Login Card */}
        <div className="glass-effect rounded-3xl shadow-2xl p-8 hover-lift">
          <div className="mb-8">
            <div className="text-center py-3">
              <h2 className="text-xl font-semibold text-gray-800">Sign In to CipherBank</h2>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="relative">
              <input
                type="text"
                placeholder="Username"
                value={formData.username}
                onChange={(e) => setFormData({...formData, username: e.target.value})}
                className="w-full px-4 py-4 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300 bg-white/50"
                required
              />
            </div>

            <div className="relative">
              <input
                type="password"
                placeholder="Password"
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
                className="w-full px-4 py-4 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300 bg-white/50"
                required
              />
            </div>

            <button
              type="submit"
              className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-4 rounded-xl font-semibold shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-105"
            >
              Sign In
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-600">
            <p>BETA V1</p>
          </div>
        </div>
      </div>
    </div>
  );
};
// Dashboard Layout
const DashboardLayout = ({ currentView, setCurrentView, user, token, setUser, setToken, handleLogout, showNotification, isMenuOpen, setIsMenuOpen }) => {

  // Validate token on every render of protected pages
  useEffect(() => {
    // Only check if token exists, don't validate it
    if (!token) {
      console.log('No token found, redirecting to login');
      setCurrentView('login');
    }
  }, [currentView, token]);

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <Sidebar
        currentView={currentView}
        setCurrentView={setCurrentView}
        user={user}
        handleLogout={handleLogout}
        isMenuOpen={isMenuOpen}
        setIsMenuOpen={setIsMenuOpen}
      />

      {/* Main Content */}
      <div className="flex-1 lg:ml-72">
        <Header user={user} setIsMenuOpen={setIsMenuOpen} />
        <main className="p-6 lg:p-8">
          {currentView === 'dashboard' && <Dashboard token={token} showNotification={showNotification} />}
          {currentView === 'upload' && <UploadView token={token} showNotification={showNotification} setCurrentView={setCurrentView} setUser={setUser} setToken={setToken} />}
          {currentView === 'statements' && <StatementsView token={token} showNotification={showNotification} />}
          {currentView === 'users' && <UserManagementView token={token} showNotification={showNotification} setCurrentView={setCurrentView} setUser={setUser} setToken={setToken} />}
          {currentView === 'changepassword' && <ChangePasswordView token={token} user={user} showNotification={showNotification} setCurrentView={setCurrentView} setUser={setUser} setToken={setToken} />}
        </main>
      </div>
    </div>
  );
};

// Sidebar Component
const Sidebar = ({ currentView, setCurrentView, user, handleLogout, isMenuOpen, setIsMenuOpen }) => {
  // Check if user is admin
  const isAdmin = user?.roles?.includes('ROLE_ADMIN') || false;

  // Build menu items based on role
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'upload', label: 'Upload Statement', icon: Upload },
    { id: 'statements', label: 'Statements', icon: FileText },
    // Only show User Management for admins
    ...(isAdmin ? [{ id: 'users', label: 'User Management', icon: Users }] : []),
    { id: 'changepassword', label: 'Change Password', icon: Key },
  ];
  return (
    <>
      {/* Mobile Overlay */}
      {isMenuOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setIsMenuOpen(false)}
        ></div>
      )}

      {/* Sidebar */}
      <aside className={`fixed top-0 left-0 h-full w-72 bg-gradient-to-b from-slate-900 to-slate-800 text-white p-6 z-50 transition-transform duration-300 ${
        isMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
      }`}>
        {/* Close button for mobile */}
        <button
          onClick={() => setIsMenuOpen(false)}
          className="lg:hidden absolute top-6 right-6 text-white"
        >
          <X className="w-6 h-6" />
        </button>

        {/* Logo */}
        <div className="flex items-center gap-3 mb-10">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-xl flex items-center justify-center">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold">CipherBank</h2>
            <p className="text-xs text-gray-400">Automated Statement Parsing</p>
          </div>
        </div>

        {/* User Info */}
        <div className="bg-white/10 rounded-xl p-4 mb-8 backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-400 to-indigo-500 rounded-full flex items-center justify-center">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <p className="font-semibold">{user?.username || 'User'}</p>
              <p className="text-xs text-gray-400">
                {user?.roles?.includes('ROLE_ADMIN') ? 'Administrator' : 'User'}
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;
            
            return (
              <button
                key={item.id}
                onClick={() => {
                  setCurrentView(item.id);
                  setIsMenuOpen(false);
                }}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 ${
                  isActive 
                    ? 'bg-gradient-to-r from-blue-500 to-indigo-600 shadow-lg' 
                    : 'hover:bg-white/10'
                }`}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
                {isActive && <ChevronRight className="w-4 h-4 ml-auto" />}
              </button>
            );
          })}
        </nav>

        {/* Logout Button */}
        <button
          onClick={handleLogout}
          className="absolute bottom-6 left-6 right-6 flex items-center justify-center gap-3 px-4 py-3 rounded-xl bg-red-500/20 hover:bg-red-500/30 transition-all duration-300"
        >
          <LogOut className="w-5 h-5" />
          <span className="font-medium">Logout</span>
        </button>
      </aside>
    </>
  );
};

// Header Component
const Header = ({ user, setIsMenuOpen }) => {
  return (
    <header className="bg-white border-b border-gray-200 px-6 py-4 lg:px-8">
      <div className="flex items-center justify-between">
        <button
          onClick={() => setIsMenuOpen(true)}
          className="lg:hidden text-gray-600 hover:text-gray-900"
        >
          <Menu className="w-6 h-6" />
        </button>

        <div className="flex-1 lg:flex-none">
          <h1 className="text-2xl font-bold text-gray-900">Welcome back, {user?.username}!</h1>
          <p className="text-sm text-gray-600 mt-1">Manage your bank statements efficiently</p>
        </div>

        <div className="hidden lg:flex items-center gap-4">
          <div className="relative">
            <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search statements..."
              className="pl-10 pr-4 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 w-64"
            />
          </div>
        </div>
      </div>
    </header>
  );
};

// Dashboard View
const Dashboard = ({ token, showNotification }) => {
  const [stats, setStats] = useState({
    totalUploads: 0,
    totalTransactions: 0,
    totalAmount: 0,
    recentUploads: []
  });

  useEffect(() => {
    // Mock data - replace with actual API calls
    setStats({
      totalUploads: 127,
      totalTransactions: 1543,
      totalAmount: 2847563.50,
      recentUploads: [
        { id: 1, bank: 'IOB', filename: 'statement_nov_2024.csv', date: '2024-11-28', rows: 45, status: 'success' },
        { id: 2, bank: 'KGB', filename: 'kerala_gramin_oct.xlsx', date: '2024-11-27', rows: 89, status: 'success' },
        { id: 3, bank: 'Indian Bank', filename: 'indianbank_sep.xlsx', date: '2024-11-26', rows: 67, status: 'success' },
      ]
    });
  }, [token]);

  const statCards = [
    { 
      title: 'Total Uploads', 
      value: stats.totalUploads, 
      icon: Upload, 
      color: 'from-blue-500 to-blue-600',
      bgColor: 'bg-blue-50'
    },
    { 
      title: 'Transactions', 
      value: stats.totalTransactions, 
      icon: Activity, 
      color: 'from-purple-500 to-purple-600',
      bgColor: 'bg-purple-50'
    },
    { 
      title: 'Total Amount', 
      value: `₹${stats.totalAmount.toLocaleString('en-IN')}`, 
      icon: DollarSign, 
      color: 'from-emerald-500 to-emerald-600',
      bgColor: 'bg-emerald-50'
    },
    { 
      title: 'Success Rate', 
      value: '98.5%', 
      icon: TrendingUp, 
      color: 'from-orange-500 to-orange-600',
      bgColor: 'bg-orange-50'
    },
  ];

  return (
    <div className="space-y-6 animate-fadeInUp">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div 
              key={stat.title} 
              className="glass-effect rounded-2xl p-6 hover-lift"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className="flex items-center justify-between mb-4">
                <div className={`w-12 h-12 ${stat.bgColor} rounded-xl flex items-center justify-center`}>
                  <Icon className={`w-6 h-6 bg-gradient-to-r ${stat.color} text-transparent`} style={{WebkitBackgroundClip: 'text'}} />
                </div>
                <span className="text-xs font-semibold text-emerald-600">+12.5%</span>
              </div>
              <h3 className="text-gray-600 text-sm mb-1">{stat.title}</h3>
              <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
            </div>
          );
        })}
      </div>

      {/* Recent Uploads */}
      <div className="glass-effect rounded-2xl p-6 lg:p-8">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-gray-900">Recent Uploads</h2>
          <button className="text-blue-600 hover:text-blue-700 font-medium text-sm flex items-center gap-2">
            View All
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Bank</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Filename</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Date</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Rows</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Status</th>
              </tr>
            </thead>
            <tbody>
              {stats.recentUploads.map((upload, index) => (
                <tr 
                  key={upload.id} 
                  className="border-b border-gray-100 hover:bg-gray-50 transition-colors duration-200"
                  style={{ animation: `fadeInUp 0.4s ease-out ${index * 0.1}s backwards` }}
                >
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                        <FileText className="w-4 h-4 text-blue-600" />
                      </div>
                      <span className="font-medium text-gray-900">{upload.bank}</span>
                    </div>
                  </td>
                  <td className="py-4 px-4 text-gray-600">{upload.filename}</td>
                  <td className="py-4 px-4 text-gray-600">{upload.date}</td>
                  <td className="py-4 px-4 text-gray-600">{upload.rows}</td>
                  <td className="py-4 px-4">
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-emerald-100 text-emerald-700 text-sm font-medium">
                      <CheckCircle className="w-4 h-4" />
                      Success
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// Upload View
const UploadView = ({ token, showNotification, setCurrentView, setUser, setToken }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadData, setUploadData] = useState({
    parserKey: 'iob',
    username: 'admin',
    accountNo: '',
    file: null
  });
  const [uploading, setUploading] = useState(false);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) {
      setUploadData({ ...uploadData, file });
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setUploadData({ ...uploadData, file });
    }
  };

  const handleUpload = async () => {

    if (!uploadData.file) {
      showNotification('Please select a file', 'error');
      return;
    }

    setUploading(true);

    try {
      const formData = new FormData();
      formData.append('file', uploadData.file);
      formData.append('parserKey', uploadData.parserKey);
      formData.append('username', uploadData.username);
      if (uploadData.accountNo) {
        formData.append('accountNo', uploadData.accountNo);
      }

      const response = await fetch(`${API_BASE_URL}/statements/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });

      // Check for 401/403 - token expired
      if (response.status === 401 || response.status === 403) {
        showNotification('Session expired. Please login again.', 'error');
        setTimeout(() => {
          clearSessionAndRedirect(setCurrentView, setUser, setToken, null, 'upload');
        }, 1500);
        return;
      }

      const data = await response.json();

      if (response.ok) {
        showNotification(`Upload successful! Processed ${data.rowsParsed} rows (${data.rowsInserted} new, ${data.rowsDeduped} duplicates)`, 'success');
        setUploadData({ ...uploadData, file: null, accountNo: '' });
      } else {
        showNotification(data.message || 'Upload failed', 'error');
      }

    } catch (error) {
      showNotification('Upload failed. Please try again.', 'error');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto animate-fadeInUp">
      <div className="glass-effect rounded-2xl p-8 lg:p-10">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Upload Bank Statement</h2>
        <p className="text-gray-600 mb-8">Upload CSV, XLS, XLSX, or PDF bank statements for processing</p>

        {/* Bank Selection */}
        <div className="mb-6">
          <label className="block text-sm font-semibold text-gray-700 mb-3">Select Bank</label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {['iob', 'kgb', 'indianbank'].map((bank) => (
              <button
                key={bank}
                onClick={() => setUploadData({ ...uploadData, parserKey: bank })}
                className={`p-4 rounded-xl border-2 transition-all duration-300 ${
                  uploadData.parserKey === bank
                    ? 'border-blue-500 bg-blue-50 shadow-lg transform scale-105'
                    : 'border-gray-200 hover:border-blue-300'
                }`}
              >
                <div className="font-semibold text-gray-900">
                  {bank === 'iob' && 'Indian Overseas Bank'}
                  {bank === 'kgb' && 'Kerala Gramin Bank'}
                  {bank === 'indianbank' && 'Indian Bank'}
                </div>
                <div className="text-sm text-gray-600 mt-1">
                  {bank === 'iob' && 'CSV Format'}
                  {bank === 'kgb' && 'XLS/XLSX Format'}
                  {bank === 'indianbank' && 'XLS/XLSX Format'}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Account Number (optional for IOB) */}
        {uploadData.parserKey === 'iob' && (
          <div className="mb-6">
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Account Number <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={uploadData.accountNo}
              onChange={(e) => setUploadData({ ...uploadData, accountNo: e.target.value })}
              placeholder="Enter account number"
              className="w-full px-4 py-3 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
              required
            />
            <p className="text-sm text-gray-600 mt-2">Required for IOB statements</p>
          </div>
        )}

        {/* File Upload Area */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all duration-300 ${
            isDragging
              ? 'border-blue-500 bg-blue-50 scale-105'
              : 'border-gray-300 hover:border-blue-400'
          }`}
        >
          <div className="flex flex-col items-center">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center mb-4 transition-all duration-300 ${
              uploadData.file ? 'bg-emerald-100' : 'bg-blue-100'
            }`}>
              {uploadData.file ? (
                <CheckCircle className="w-8 h-8 text-emerald-600" />
              ) : (
                <Upload className="w-8 h-8 text-blue-600" />
              )}
            </div>

            {uploadData.file ? (
              <>
                <p className="text-lg font-semibold text-gray-900 mb-2">{uploadData.file.name}</p>
                <p className="text-sm text-gray-600 mb-4">
                  {(uploadData.file.size / 1024).toFixed(2)} KB
                </p>
                <button
                  onClick={() => setUploadData({ ...uploadData, file: null })}
                  className="text-red-600 hover:text-red-700 font-medium text-sm"
                >
                  Remove file
                </button>
              </>
            ) : (
              <>
                <p className="text-lg font-semibold text-gray-900 mb-2">
                  Drag and drop your file here
                </p>
                <p className="text-sm text-gray-600 mb-4">or</p>
                <label className="cursor-pointer">
                  <span className="px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-xl font-semibold hover:shadow-lg transition-all duration-300 inline-block">
                    Browse Files
                  </span>
                  <input
                    type="file"
                    onChange={handleFileSelect}
                    accept=".csv,.xls,.xlsx,.pdf"
                    className="hidden"
                  />
                </label>
                <p className="text-xs text-gray-500 mt-4">
                  Supported formats: CSV, XLS, XLSX, PDF (Max 10MB)
                </p>
              </>
            )}
          </div>
        </div>

        {/* Upload Button */}
        <button
          onClick={handleUpload}
          disabled={!uploadData.file || uploading}
          className={`w-full mt-6 py-4 rounded-xl font-semibold text-white transition-all duration-300 ${
            uploadData.file && !uploading
              ? 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:shadow-xl transform hover:scale-105'
              : 'bg-gray-300 cursor-not-allowed'
          }`}
        >
          {uploading ? (
            <span className="flex items-center justify-center gap-3">
              <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              Processing...
            </span>
          ) : (
            'Upload Statement'
          )}
        </button>
      </div>
    </div>
  );
};

// Statements View
const StatementsView = ({ token, showNotification }) => {
  const [statements, setStatements] = useState([]);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    // Mock data - replace with actual API call
    setStatements([
      { id: 1, date: '2024-11-28', bank: 'IOB', filename: 'statement_nov.csv', transactions: 45, amount: 125000, status: 'processed' },
      { id: 2, date: '2024-11-27', bank: 'KGB', filename: 'kerala_oct.xlsx', transactions: 89, amount: 287500, status: 'processed' },
      { id: 3, date: '2024-11-26', bank: 'Indian Bank', filename: 'indianbank_sep.xlsx', transactions: 67, amount: 198750, status: 'processed' },
      { id: 4, date: '2024-11-25', bank: 'IOB', filename: 'statement_aug.csv', transactions: 52, amount: 164320, status: 'pending' },
      { id: 5, date: '2024-11-24', bank: 'KGB', filename: 'kerala_jul.xlsx', transactions: 78, amount: 234650, status: 'processed' },
    ]);
  }, [token]);

  const filteredStatements = statements.filter(stmt => {
    const matchesFilter = filter === 'all' || stmt.status === filter;
    const matchesSearch = stmt.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         stmt.bank.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="animate-fadeInUp">
      <div className="glass-effect rounded-2xl p-6 lg:p-8">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between mb-6 gap-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Statement History</h2>
            <p className="text-gray-600 mt-1">View and manage all uploaded statements</p>
          </div>

          <div className="flex gap-3">
            <div className="relative flex-1 lg:flex-none">
              <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search statements..."
                className="pl-10 pr-4 py-2 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 w-full lg:w-64"
              />
            </div>
            <button className="px-4 py-2 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition-colors duration-300 flex items-center gap-2">
              <Filter className="w-4 h-4" />
              <span className="hidden sm:inline">Filter</span>
            </button>
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex gap-3 mb-6 overflow-x-auto pb-2">
          {['all', 'processed', 'pending'].map((status) => (
            <button
              key={status}
              onClick={() => setFilter(status)}
              className={`px-4 py-2 rounded-xl font-medium transition-all duration-300 whitespace-nowrap ${
                filter === status
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>

        {/* Statements Table */}
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Date</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Bank</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Filename</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Transactions</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Amount</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Status</th>
                <th className="text-left py-3 px-4 text-sm font-semibold text-gray-600">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredStatements.map((stmt, index) => (
                <tr 
                  key={stmt.id}
                  className="border-b border-gray-100 hover:bg-gray-50 transition-colors duration-200"
                  style={{ animation: `fadeInUp 0.4s ease-out ${index * 0.1}s backwards` }}
                >
                  <td className="py-4 px-4 text-gray-600">{stmt.date}</td>
                  <td className="py-4 px-4">
                    <span className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-blue-100 text-blue-700 text-sm font-medium">
                      <FileText className="w-4 h-4" />
                      {stmt.bank}
                    </span>
                  </td>
                  <td className="py-4 px-4 text-gray-900 font-medium">{stmt.filename}</td>
                  <td className="py-4 px-4 text-gray-600">{stmt.transactions}</td>
                  <td className="py-4 px-4 text-gray-900 font-semibold">₹{stmt.amount.toLocaleString('en-IN')}</td>
                  <td className="py-4 px-4">
                    <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium ${
                      stmt.status === 'processed'
                        ? 'bg-emerald-100 text-emerald-700'
                        : 'bg-yellow-100 text-yellow-700'
                    }`}>
                      {stmt.status === 'processed' ? (
                        <CheckCircle className="w-4 h-4" />
                      ) : (
                        <Activity className="w-4 h-4 animate-spin" />
                      )}
                      {stmt.status.charAt(0).toUpperCase() + stmt.status.slice(1)}
                    </span>
                  </td>
                  <td className="py-4 px-4">
                    <button className="text-blue-600 hover:text-blue-700 transition-colors duration-200">
                      <Download className="w-5 h-5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Empty State */}
        {filteredStatements.length === 0 && (
          <div className="text-center py-12">
            <FileText className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-600">No statements found</p>
          </div>
        )}
      </div>
    </div>
  );
};
// User Management View
const UserManagementView = ({ token, showNotification, setCurrentView, setUser, setToken }) => {
  const [newUser, setNewUser] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    roleIds: [2], // Default to USER role (id: 2)
    selectedRole: 'user' // 'user' or 'admin'
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [creating, setCreating] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);

  // Calculate password strength
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

  // Get strength color
  const getStrengthColor = (strength) => {
    if (strength < 40) return 'bg-red-500';
    if (strength < 70) return 'bg-yellow-500';
    return 'bg-emerald-500';
  };

  // Get strength text
  const getStrengthText = (strength) => {
    if (strength < 40) return 'Weak';
    if (strength < 70) return 'Medium';
    return 'Strong';
  };

  // Generate secure password
  const generatePassword = () => {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const special = '!@#$%^&*';
    const allChars = lowercase + uppercase + numbers + special;

    let password = '';
    // Ensure at least one of each type
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += special[Math.floor(Math.random() * special.length)];

    // Fill the rest randomly
    for (let i = 4; i < 16; i++) {
      password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    // Shuffle the password
    password = password.split('').sort(() => Math.random() - 0.5).join('');

    setNewUser({ ...newUser, password, confirmPassword: password });
    setPasswordStrength(calculatePasswordStrength(password));
    showNotification('Secure password generated!', 'success');
  };

  // Copy password to clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    showNotification('Password copied to clipboard!', 'success');
  };

  // Update password strength when password changes
  useEffect(() => {
    setPasswordStrength(calculatePasswordStrength(newUser.password));
  }, [newUser.password]);

  // Password requirements check
  const requirements = [
    { label: 'At least 8 characters', met: newUser.password.length >= 8 },
    { label: 'Uppercase letter', met: /[A-Z]/.test(newUser.password) },
    { label: 'Lowercase letter', met: /[a-z]/.test(newUser.password) },
    { label: 'Number', met: /[0-9]/.test(newUser.password) },
    { label: 'Special character', met: /[^a-zA-Z0-9]/.test(newUser.password) },
  ];

  const handleCreateUser = async (e) => {
    e.preventDefault();
    // Validate token before API call
    if (!token) {
      showNotification('Session expired. Please login again.', 'error');
      setTimeout(() => {
        clearSessionAndRedirect(setCurrentView, setUser, setToken, null);
      }, 2000);
      return;
    }
    // Validation
    if (newUser.username.length < 3) {
      showNotification('Username must be at least 3 characters long', 'error');
      return;
    }

    if (newUser.password.length < 8) {
      showNotification('Password must be at least 8 characters long', 'error');
      return;
    }

    if (newUser.password !== newUser.confirmPassword) {
      showNotification('Passwords do not match', 'error');
      return;
    }

    if (passwordStrength < 40) {
      showNotification('Password is too weak. Please use a stronger password.', 'error');
      return;
    }

    setCreating(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          username: newUser.username,
          password: newUser.password,
          roleIds: newUser.roleIds
        }),
      });

      const data = await response.json();

      if (response.ok) {
        const roleText = newUser.selectedRole === 'admin' ? 'Administrator' : 'User';
        showNotification(`${roleText} "${newUser.username}" created successfully!`, 'success');
        setNewUser({
          username: '',
          password: '',
          confirmPassword: '',
          roleIds: [2],
          selectedRole: 'user'  // Reset to default role
        });

        setPasswordStrength(0);
      } else {
        // Handle specific error codes
        if (response.status === 403) {
          showNotification('Access denied. Only administrators can create users.', 'error');
        } else if (response.status === 409 || (data.message && data.message.includes('already exists'))) {
          showNotification('Username already exists. Please choose a different username.', 'error');
        } else {
          showNotification(data.message || 'Failed to create user', 'error');
        }
      }

    } catch (error) {
      showNotification('Failed to create user. Please try again.', 'error');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto animate-fadeInUp">
      <div className="glass-effect rounded-2xl p-8 lg:p-10">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-2xl flex items-center justify-center">
            <Users className="w-8 h-8 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-gray-900">User Management</h2>
            <p className="text-gray-600">Create new user accounts with secure credentials</p>
          </div>
        </div>

        <form onSubmit={handleCreateUser} className="space-y-6">
          {/* Username */}
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Username <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newUser.username}
              onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
              placeholder="Enter username"
              className="w-full px-4 py-3 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
              required
            />
          </div>
          {/* ADD THIS NEW SECTION - Role Selection */}
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Role <span className="text-red-500">*</span>
            </label>
            <div className="grid grid-cols-2 gap-4">
              <button
                type="button"
                onClick={() => setNewUser({ ...newUser, selectedRole: 'user', roleIds: [2] })}
                className={`p-4 rounded-xl border-2 transition-all duration-300 ${
                  newUser.selectedRole === 'user'
                    ? 'border-blue-500 bg-blue-50 shadow-lg'
                    : 'border-gray-200 hover:border-blue-300'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    newUser.selectedRole === 'user' ? 'bg-blue-500' : 'bg-gray-300'
                  }`}>
                    <Users className="w-5 h-5 text-white" />
                  </div>
                  <div className="text-left">
                    <div className="font-semibold text-gray-900">User</div>
                    <div className="text-sm text-gray-600">Standard access</div>
                  </div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setNewUser({ ...newUser, selectedRole: 'admin', roleIds: [1, 2] })}
                className={`p-4 rounded-xl border-2 transition-all duration-300 ${
                  newUser.selectedRole === 'admin'
                    ? 'border-purple-500 bg-purple-50 shadow-lg'
                    : 'border-gray-200 hover:border-purple-300'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    newUser.selectedRole === 'admin' ? 'bg-purple-500' : 'bg-gray-300'
                  }`}>
                    <Shield className="w-5 h-5 text-white" />
                  </div>
                  <div className="text-left">
                    <div className="font-semibold text-gray-900">Administrator</div>
                    <div className="text-sm text-gray-600">Full access</div>
                  </div>
                </div>
              </button>
            </div>
            <p className="text-sm text-gray-600 mt-2">
              {newUser.selectedRole === 'admin'
                ? '⚠️ Administrators can create users and access all features'
                : 'Users can upload statements and view their data'}
            </p>
          </div>

          {/* Password */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="block text-sm font-semibold text-gray-700">
                Password <span className="text-red-500">*</span>
              </label>
              <button
                type="button"
                onClick={generatePassword}
                className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
              >
                <RefreshCw className="w-4 h-4" />
                Generate Password
              </button>
            </div>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                placeholder="Enter password"
                className="w-full px-4 py-3 pr-24 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
              />
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2 flex gap-2">
                <button
                  type="button"
                  onClick={() => copyToClipboard(newUser.password)}
                  className="text-gray-400 hover:text-gray-600"
                  disabled={!newUser.password}
                >
                  <Copy className="w-5 h-5" />
                </button>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* Password Strength Meter */}
            {newUser.password && (
              <div className="mt-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-600">Password Strength:</span>
                  <span className={`text-sm font-semibold ${
                    passwordStrength < 40 ? 'text-red-600' :
                    passwordStrength < 70 ? 'text-yellow-600' : 'text-emerald-600'
                  }`}>
                    {getStrengthText(passwordStrength)}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${getStrengthColor(passwordStrength)}`}
                    style={{ width: `${passwordStrength}%` }}
                  ></div>
                </div>
              </div>
            )}

            {/* Password Requirements */}
            <div className="mt-4 space-y-2">
              {requirements.map((req, index) => (
                <div key={index} className="flex items-center gap-2">
                  <CheckCircle className={`w-4 h-4 ${req.met ? 'text-emerald-500' : 'text-gray-300'}`} />
                  <span className={`text-sm ${req.met ? 'text-gray-700' : 'text-gray-400'}`}>
                    {req.label}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Confirm Password */}
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Confirm Password <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                value={newUser.confirmPassword}
                onChange={(e) => setNewUser({ ...newUser, confirmPassword: e.target.value })}
                placeholder="Confirm password"
                className="w-full px-4 py-3 pr-12 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            {newUser.confirmPassword && (
              <div className="mt-2 flex items-center gap-2">
                {newUser.password === newUser.confirmPassword ? (
                  <>
                    <CheckCircle className="w-4 h-4 text-emerald-500" />
                    <span className="text-sm text-emerald-600">Passwords match</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 text-red-500" />
                    <span className="text-sm text-red-600">Passwords do not match</span>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={creating || passwordStrength < 40}
            className={`w-full py-4 rounded-xl font-semibold text-white transition-all duration-300 ${
              !creating && passwordStrength >= 40
                ? 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:shadow-xl transform hover:scale-105'
                : 'bg-gray-300 cursor-not-allowed'
            }`}
          >
            {creating ? (
              <span className="flex items-center justify-center gap-3">
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Creating User...
              </span>
            ) : (
              'Create User'
            )}
          </button>
        </form>
      </div>
    </div>
  );
};
// Change Password View
const ChangePasswordView = ({ token, user, showNotification, setCurrentView, setUser, setToken }) => {
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

  // Calculate password strength
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

  // Get strength color
  const getStrengthColor = (strength) => {
    if (strength < 40) return 'bg-red-500';
    if (strength < 70) return 'bg-yellow-500';
    return 'bg-emerald-500';
  };

  // Get strength text
  const getStrengthText = (strength) => {
    if (strength < 40) return 'Weak';
    if (strength < 70) return 'Medium';
    return 'Strong';
  };

  // Generate secure password
  const generatePassword = () => {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const special = '!@#$%^&*';
    const allChars = lowercase + uppercase + numbers + special;

    let password = '';
    // Ensure at least one of each type
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += special[Math.floor(Math.random() * special.length)];

    // Fill the rest randomly
    for (let i = 4; i < 16; i++) {
      password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    // Shuffle the password
    password = password.split('').sort(() => Math.random() - 0.5).join('');

    setPasswordData({ ...passwordData, newPassword: password, confirmNewPassword: password });
    setPasswordStrength(calculatePasswordStrength(password));
    showNotification('Secure password generated!', 'success');
  };

  // Copy password to clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    showNotification('Password copied to clipboard!', 'success');
  };

  // Update password strength when password changes
  useEffect(() => {
    setPasswordStrength(calculatePasswordStrength(passwordData.newPassword));
  }, [passwordData.newPassword]);

  // Password requirements check
  const requirements = [
    { label: 'At least 8 characters', met: passwordData.newPassword.length >= 8 },
    { label: 'Uppercase letter', met: /[A-Z]/.test(passwordData.newPassword) },
    { label: 'Lowercase letter', met: /[a-z]/.test(passwordData.newPassword) },
    { label: 'Number', met: /[0-9]/.test(passwordData.newPassword) },
    { label: 'Special character', met: /[^a-zA-Z0-9]/.test(passwordData.newPassword) },
  ];

  const handleChangePassword = async (e) => {
    e.preventDefault();
    // Validate token before API call
    if (!token) {
      showNotification('Session expired. Please login again.', 'error');
      setTimeout(() => {
        clearSessionAndRedirect(setCurrentView, setUser, setToken, null);
      }, 2000);
      return;
    }
    // Validation
    if (!passwordData.currentPassword) {
      showNotification('Please enter your current password', 'error');
      return;
    }

    if (passwordData.newPassword.length < 8) {
      showNotification('New password must be at least 8 characters long', 'error');
      return;
    }

    if (passwordData.newPassword !== passwordData.confirmNewPassword) {
      showNotification('New passwords do not match', 'error');
      return;
    }

    if (passwordStrength < 40) {
      showNotification('New password is too weak. Please use a stronger password.', 'error');
      return;
    }

    if (passwordData.currentPassword === passwordData.newPassword) {
      showNotification('New password must be different from current password', 'error');
      return;
    }

    setChanging(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/change-password`, {
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

      const data = await response.json();

      if (response.ok) {
        showNotification('Password changed successfully!', 'success');
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmNewPassword: ''
        });
        setPasswordStrength(0);
      } else {
        showNotification(data.message || 'Failed to change password', 'error');
      }
    } catch (error) {
      showNotification('Failed to change password. Please try again.', 'error');
    } finally {
      setChanging(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto animate-fadeInUp">
      <div className="glass-effect rounded-2xl p-8 lg:p-10">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl flex items-center justify-center">
            <Key className="w-8 h-8 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Change Password</h2>
            <p className="text-gray-600">Update your account password securely</p>
          </div>
        </div>

        {/* User Info */}
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center">
              <Users className="w-5 h-5 text-white" />
            </div>
            <div>
              <p className="text-sm text-gray-600">Changing password for</p>
              <p className="font-semibold text-gray-900">{user?.username}</p>
            </div>
          </div>
        </div>

        <form onSubmit={handleChangePassword} className="space-y-6">
          {/* Current Password */}
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Current Password <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <input
                type={showCurrentPassword ? 'text' : 'password'}
                value={passwordData.currentPassword}
                onChange={(e) => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                placeholder="Enter current password"
                className="w-full px-4 py-3 pr-12 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
              />
              <button
                type="button"
                onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showCurrentPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {/* New Password */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="block text-sm font-semibold text-gray-700">
                New Password <span className="text-red-500">*</span>
              </label>
              <button
                type="button"
                onClick={generatePassword}
                className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
              >
                <RefreshCw className="w-4 h-4" />
                Generate Password
              </button>
            </div>
            <div className="relative">
              <input
                type={showNewPassword ? 'text' : 'password'}
                value={passwordData.newPassword}
                onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                placeholder="Enter new password"
                className="w-full px-4 py-3 pr-24 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
              />
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2 flex gap-2">
                <button
                  type="button"
                  onClick={() => copyToClipboard(passwordData.newPassword)}
                  className="text-gray-400 hover:text-gray-600"
                  disabled={!passwordData.newPassword}
                >
                  <Copy className="w-5 h-5" />
                </button>
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  {showNewPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* Password Strength Meter */}
            {passwordData.newPassword && (
              <div className="mt-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-600">Password Strength:</span>
                  <span className={`text-sm font-semibold ${
                    passwordStrength < 40 ? 'text-red-600' :
                    passwordStrength < 70 ? 'text-yellow-600' : 'text-emerald-600'
                  }`}>
                    {getStrengthText(passwordStrength)}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${getStrengthColor(passwordStrength)}`}
                    style={{ width: `${passwordStrength}%` }}
                  ></div>
                </div>
              </div>
            )}

            {/* Password Requirements */}
            <div className="mt-4 space-y-2">
              {requirements.map((req, index) => (
                <div key={index} className="flex items-center gap-2">
                  <CheckCircle className={`w-4 h-4 ${req.met ? 'text-emerald-500' : 'text-gray-300'}`} />
                  <span className={`text-sm ${req.met ? 'text-gray-700' : 'text-gray-400'}`}>
                    {req.label}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Confirm New Password */}
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Confirm New Password <span className="text-red-500">*</span>
            </label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                value={passwordData.confirmNewPassword}
                onChange={(e) => setPasswordData({ ...passwordData, confirmNewPassword: e.target.value })}
                placeholder="Confirm new password"
                className="w-full px-4 py-3 pr-12 rounded-xl border-2 border-gray-200 focus:border-blue-500 focus:outline-none transition-all duration-300"
                required
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            {passwordData.confirmNewPassword && (
              <div className="mt-2 flex items-center gap-2">
                {passwordData.newPassword === passwordData.confirmNewPassword ? (
                  <>
                    <CheckCircle className="w-4 h-4 text-emerald-500" />
                    <span className="text-sm text-emerald-600">Passwords match</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 text-red-500" />
                    <span className="text-sm text-red-600">Passwords do not match</span>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={changing || passwordStrength < 40}
            className={`w-full py-4 rounded-xl font-semibold text-white transition-all duration-300 ${
              !changing && passwordStrength >= 40
                ? 'bg-gradient-to-r from-indigo-600 to-purple-600 hover:shadow-xl transform hover:scale-105'
                : 'bg-gray-300 cursor-not-allowed'
            }`}
          >
            {changing ? (
              <span className="flex items-center justify-center gap-3">
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Changing Password...
              </span>
            ) : (
              'Change Password'
            )}
          </button>
        </form>

        {/* Security Tip */}
        <div className="mt-6 bg-yellow-50 border border-yellow-200 rounded-xl p-4">
          <div className="flex gap-3">
            <Shield className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-yellow-800 mb-1">Security Tips</p>
              <ul className="text-sm text-yellow-700 space-y-1">
                <li>• Use a unique password you don't use anywhere else</li>
                <li>• Consider using a password manager</li>
                <li>• Change your password regularly</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
export default CipherBankUI;
