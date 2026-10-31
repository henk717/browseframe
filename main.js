const { app, BrowserWindow, Menu, shell, ipcMain } = require('electron');
const path = require('path');
const { installSystemCA } = require('./system-ca');

let mainWindow;

function createWindow(url) {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      partition: 'temporary-session',
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      webviewTag: false,
      sandbox: true
    },
    titleBarStyle: 'hidden',
    frame: true,
    menuBarVisible: false
  });

  // Unified popup handler — preload survives in popups
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // Block non-http(s) protocols
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      shell.openExternal(url);
      return { action: 'deny' };
    }

    // Allow popup but enforce preload + security
    return {
      action: 'allow',
      overrideBrowserWindowOptions: {
        webPreferences: {
          partition: 'temporary-session',
          preload: path.join(__dirname, 'preload.js'),
          contextIsolation: true,
          nodeIntegration: false,
          sandbox: true,
          webviewTag: false
        }
      }
    };
  });

  // Verify TLS against the Linux system trust store (/etc/ssl/certs) instead of
  // the CA snapshot compiled into the bundled Chromium. Must be installed
  // before the first loadURL() of this session.
  const ses = mainWindow.webContents.session;
  installSystemCA(ses);

  // Intercept downloads

  ses.on('will-download', (event, item) => {
    event.preventDefault(); // Stop the download dialog
  });

  // Set window title based on URL
  if (url) {
    try {
      const urlObj = new URL(url);
      mainWindow.setTitle(urlObj.hostname || '');
    } catch {
      mainWindow.setTitle('');
    }
  }

  // Load URL or blank page
  if (url) {
    mainWindow.loadURL(url);
  } else {
    mainWindow.loadFile(path.join(__dirname, 'blank.html'));
  }

  // Keep title synced
  mainWindow.webContents.on('did-finish-load', () => {
    const title = mainWindow.webContents.getTitle();
    mainWindow.setTitle(title || '');
  });

  mainWindow.webContents.on('page-title-updated', (event, title) => {
    mainWindow.setTitle(title || '');
  });

  // Remove application menu
  Menu.setApplicationMenu(null);

  // Block navigation to file:// and non-http(s) protocols
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (url.startsWith('file://')) {
      event.preventDefault();
      return;
    }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  // Block legacy new-window events
  mainWindow.webContents.on('new-window', (event, url) => {
    event.preventDefault();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      shell.openExternal(url);
    }
  });

  // File dialog blocking (Electron-side)
  ipcMain.handle('dialog:openFile', async () => null);
  ipcMain.handle('dialog:saveFile', async () => null);
}

function getCommandLineUrl() {
  const args = process.argv.slice(1);

  for (const arg of args) {
    if (arg.startsWith('-')) continue;
    if (arg === __filename) continue;

    if (arg.startsWith('http://') || arg.startsWith('https://')) {
      return arg;
    }

    if (arg.includes('.')) {
      return 'http://' + arg;
    }
  }

  return null;
}

app.whenReady().then(() => {
  const url = getCommandLineUrl();
  createWindow(url);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  app.quit();
});

app.on('open-url', (event, url) => {
  event.preventDefault();
  if (mainWindow) {
    mainWindow.loadURL(url);
  }
});
