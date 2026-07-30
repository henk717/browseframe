// Disable all existing file inputs
function disableFileInputs(root = document) {
  const inputs = root.querySelectorAll('input[type="file"]');
  inputs.forEach(input => {
    input.disabled = true;
    input.style.pointerEvents = 'none';
    input.style.opacity = '0.5';
    input.title = 'File uploads are disabled';
  });
}

window.addEventListener('DOMContentLoaded', () => {
  // Disable existing file inputs
  disableFileInputs();

  // Observe DOM changes to catch dynamically added file inputs
  const observer = new MutationObserver(mutations => {
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            disableFileInputs(node);
          }
        });
      }

      if (mutation.type === 'attributes' &&
          mutation.target.tagName === 'INPUT' &&
          mutation.target.type.toLowerCase() === 'file') {
        disableFileInputs();
      }
    }
  });

  observer.observe(document, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['type']
  });
});

// Block click activation of file inputs (capture phase)
window.addEventListener('click', event => {
  const target = event.target.closest?.('input[type="file"]');
  if (target) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
}, true);

// Block keyboard activation (Enter/Space) on file inputs
window.addEventListener('keydown', event => {
  const target = event.target.closest?.('input[type="file"]');
  if (target && (event.key === 'Enter' || event.key === ' ' || event.code === 'Space')) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
}, true);

// Block File System Access API (no native file/directory pickers)
['showOpenFilePicker', 'showSaveFilePicker', 'showDirectoryPicker'].forEach(fn => {
  if (fn in window) {
    Object.defineProperty(window, fn, {
      value: async () => {
        throw new DOMException('File access blocked', 'NotAllowedError');
      },
      writable: false,
      configurable: false
    });
  }
});

// Block print dialog
window.print = () => {
  throw new DOMException('Printing blocked', 'NotAllowedError');
};

// Block download dialog (Save As)
document.addEventListener('click', event => {
  const a = event.target.closest?.('a[download]');
  if (a) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
}, true);

document.addEventListener('contextmenu', event => {
  // Prevent "Save link as…" from right-click menu
  const a = event.target.closest?.('a');
  if (a && a.hasAttribute('download')) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
}, true);
