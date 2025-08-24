document.addEventListener('DOMContentLoaded', function() {
    // Sample URL buttons functionality
    const sampleUrlButtons = document.querySelectorAll('.sample-url');
    const urlInput = document.getElementById('url');
    const urlForm = document.getElementById('urlForm');

    sampleUrlButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const sampleUrl = this.getAttribute('data-url');
            if (urlInput) {
                urlInput.value = sampleUrl;
                urlInput.focus();
                
                // Add visual feedback
                this.classList.add('active');
                setTimeout(() => {
                    this.classList.remove('active');
                }, 200);
            }
        });
    });

    // Form submission with loading state
    if (urlForm) {
        urlForm.addEventListener('submit', function(e) {
            const submitButton = this.querySelector('button[type="submit"]');
            const originalText = submitButton.innerHTML;
            
            // Show loading state
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
            
            // Re-enable button after a delay if form doesn't submit
            setTimeout(() => {
                if (submitButton.disabled) {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalText;
                }
            }, 10000);
        });
    }

    // URL validation
    if (urlInput) {
        urlInput.addEventListener('input', function() {
            const value = this.value.trim();
            const isValid = value.length > 0;
            
            if (isValid) {
                this.classList.remove('is-invalid');
                this.classList.add('is-valid');
            } else {
                this.classList.remove('is-valid');
                this.classList.add('is-invalid');
            }
        });

        // Auto-focus on URL input
        urlInput.focus();
    }

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Copy URL functionality for results page
    const urlDisplay = document.querySelector('.url-display code');
    if (urlDisplay) {
        urlDisplay.style.cursor = 'pointer';
        urlDisplay.title = 'Click to copy URL';
        
        urlDisplay.addEventListener('click', function() {
            navigator.clipboard.writeText(this.textContent).then(() => {
                // Show temporary feedback
                const originalBg = this.style.backgroundColor;
                this.style.backgroundColor = 'rgba(25, 135, 84, 0.3)';
                this.style.transition = 'background-color 0.3s ease';
                
                setTimeout(() => {
                    this.style.backgroundColor = originalBg;
                }, 1000);
            }).catch(err => {
                console.error('Failed to copy URL:', err);
            });
        });
    }

    // Alert auto-dismiss
    const alerts = document.querySelectorAll('.alert:not(.alert-dismissible)');
    alerts.forEach(alert => {
        if (!alert.querySelector('.btn-close')) {
            setTimeout(() => {
                alert.style.opacity = '0';
                alert.style.transition = 'opacity 0.5s ease';
                setTimeout(() => {
                    if (alert.parentNode) {
                        alert.parentNode.removeChild(alert);
                    }
                }, 500);
            }, 5000);
        }
    });

    // Initialize tooltips if Bootstrap tooltips are available
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    // Feature value highlighting based on risk
    const featureValues = document.querySelectorAll('.feature-value');
    featureValues.forEach(value => {
        const text = value.textContent.toLowerCase();
        
        // Highlight potentially risky values
        if (text.includes('yes') && 
            (value.previousElementSibling.textContent.includes('IP Address') ||
             value.previousElementSibling.textContent.includes('Suspicious') ||
             value.previousElementSibling.textContent.includes('Phishing'))) {
            value.classList.add('text-danger');
        } else if (text.includes('found') && 
                   value.previousElementSibling.textContent.includes('Keywords')) {
            value.classList.add('text-danger');
        }
    });

    // Animate progress bars on results page
    const progressBars = document.querySelectorAll('.progress-bar');
    progressBars.forEach(bar => {
        const width = bar.style.width;
        bar.style.width = '0%';
        setTimeout(() => {
            bar.style.width = width;
        }, 500);
    });

    // Add keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + Enter to submit form
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && urlForm) {
            e.preventDefault();
            urlForm.submit();
        }
        
        // Escape to clear input
        if (e.key === 'Escape' && urlInput) {
            urlInput.value = '';
            urlInput.focus();
        }
    });

    console.log('PhishGuard interface initialized successfully');
});

// API helper functions for potential future use
class PhishGuardAPI {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
    }

    async predict(url) {
        try {
            const response = await fetch(`${this.baseUrl}/api/predict`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });
            
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            return { success: false, error: error.message };
        }
    }

    async predictBatch(urls) {
        try {
            const response = await fetch(`${this.baseUrl}/api/predict/batch`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ urls: urls })
            });
            
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            return { success: false, error: error.message };
        }
    }

    async getModelInfo() {
        try {
            const response = await fetch(`${this.baseUrl}/api/model/info`);
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            return { success: false, error: error.message };
        }
    }
}

// Export API class for potential external use
window.PhishGuardAPI = PhishGuardAPI;
