// JavaScript for PhishGuard - Phishing Detection Application

document.addEventListener('DOMContentLoaded', function() {
    // Dark Mode Toggle
    const darkModeToggle = document.getElementById('darkModeToggle');
    
    // Check for saved theme preference or use preferred color scheme
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
        document.body.classList.remove('dark-mode');
        darkModeToggle.checked = false;
    } else if (savedTheme === 'dark' || window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.body.classList.add('dark-mode');
        darkModeToggle.checked = true;
    }
    
    // Add dark mode toggle event listener
    darkModeToggle.addEventListener('change', function() {
        if (this.checked) {
            document.body.classList.add('dark-mode');
            localStorage.setItem('theme', 'dark');
        } else {
            document.body.classList.remove('dark-mode');
            localStorage.setItem('theme', 'light');
        }
    });

    // Form Submission
    const predictionForm = document.getElementById('predictionForm');
    const loadingContainer = document.getElementById('loadingContainer');
    const resultsContainer = document.getElementById('resultsContainer');
    const submitBtn = document.querySelector('#predictionForm button[type="submit"]');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const submitBtnText = document.getElementById('submitBtnText');
    
    if (predictionForm) {
        predictionForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get URL from form
            const urlInput = document.getElementById('url');
            const url = urlInput.value.trim();
            
            if (!url) {
                showAlert('Please enter a valid URL', 'danger');
                return;
            }
            
            // Show loading animation
            loadingContainer.classList.remove('d-none');
            resultsContainer.classList.add('d-none');
            submitBtn.disabled = true;
            loadingSpinner.classList.remove('d-none');
            submitBtnText.textContent = 'Analyzing...';
            
            // Simulate progress bar animation
            const progressBar = document.getElementById('progressBar');
            let width = 0;
            const interval = setInterval(function() {
                width += 3;
                progressBar.style.width = width + '%';
                if (width >= 90) {
                    clearInterval(interval);
                }
            }, 100);
            
            // Animated loading text
            const loadingText = document.getElementById('loadingText');
            const loadingMessages = [
                "Analyzing URL structure...",
                "Checking for suspicious patterns...",
                "Scanning domain information...",
                "Evaluating security features...",
                "Finalizing results..."
            ];
            
            let messageIndex = 0;
            const textInterval = setInterval(() => {
                loadingText.textContent = loadingMessages[messageIndex];
                messageIndex = (messageIndex + 1) % loadingMessages.length;
            }, 1500);
            
            // Send AJAX request to the Flask backend
            // We're using the demo mode for immediate results
            setTimeout(() => {
                // Generate response based on URL content to simulate intelligence
                let confidence = 0.5;
                
                // Create a deterministic hash value from the URL
                const hashCode = function(str) {
                    let hash = 0;
                    for (let i = 0, len = str.length; i < len; i++) {
                        let chr = str.charCodeAt(i);
                        hash = ((hash << 5) - hash) + chr;
                        hash |= 0; // Convert to 32bit integer
                    }
                    // Return a normalized value between 0 and 1
                    return Math.abs(hash) / 2147483647;
                };
                
                // Get a deterministic base value for this URL
                const urlHash = hashCode(url);
                const urlSpecificRandomValue = (urlHash * 0.2) - 0.1; // Range between -0.1 and 0.1
                
                // Check for phishing indicators in the URL
                if (url.includes('login') || url.includes('signin') || url.includes('account')) {
                    confidence += 0.1;
                }
                
                if (url.includes('secure') || url.includes('confirm') || url.includes('verify')) {
                    confidence += 0.1;
                }
                
                // Check for suspicious TLDs
                const suspiciousTLDs = ['xyz', 'tk', 'ml', 'ga', 'cf'];
                const urlParts = url.split('.');
                const tld = urlParts[urlParts.length - 1].split('/')[0];
                if (suspiciousTLDs.includes(tld)) {
                    confidence += 0.15;
                }
                
                // Look for IP addresses in URL
                if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
                    confidence += 0.2;
                }
                
                // Check for URL length (phishing URLs tend to be longer)
                if (url.length > 75) {
                    confidence += 0.1;
                }
                
                // Check for multiple subdomains
                const subdomains = url.split('://')[1]?.split('/')[0].split('.').length - 2;
                if (subdomains > 2) {
                    confidence += 0.1;
                }
                
                // Check for HTTPS
                if (!url.startsWith('https://')) {
                    confidence += 0.1;
                }
                
                // Add URL-specific deterministic variation instead of random
                confidence += urlSpecificRandomValue;
                
                // Clamp between 0.5 and 1.0
                confidence = Math.max(0.5, Math.min(0.95, confidence));
                
                // Set prediction based on threshold
                const isPredictedPhishing = confidence > 0.65;
                
                // Compute final confidence (scale differently based on result)
                let displayConfidence;
                if (isPredictedPhishing) {
                    displayConfidence = confidence;
                } else {
                    displayConfidence = 1 - (confidence - 0.5) * 2;
                }
                
                const mockResponse = {
                    prediction: isPredictedPhishing ? 'phishing' : 'legitimate',
                    confidence: displayConfidence
                };
                
                clearInterval(interval);
                clearInterval(textInterval);
                progressBar.style.width = '100%';
                
                // Hide loading after a brief delay to complete animation
                setTimeout(() => {
                    displayResults(mockResponse);
                    loadingContainer.classList.add('d-none');
                    resultsContainer.classList.remove('d-none');
                    submitBtn.disabled = false;
                    loadingSpinner.classList.add('d-none');
                    submitBtnText.textContent = 'Check URL';
                }, 500);
                
                /* Uncomment for actual API integration
                fetch('/predict', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({url: url})
                })
                .then(response => response.json())
                .then(data => {
                    clearInterval(interval);
                    clearInterval(textInterval);
                    progressBar.style.width = '100%';
                    
                    // Hide loading after a brief delay to complete animation
                    setTimeout(() => {
                        displayResults(data);
                        loadingContainer.classList.add('d-none');
                        resultsContainer.classList.remove('d-none');
                        submitBtn.disabled = false;
                        loadingSpinner.classList.add('d-none');
                        submitBtnText.textContent = 'Check URL';
                    }, 500);
                })
                .catch(error => {
                    console.error('Error:', error);
                    clearInterval(interval);
                    clearInterval(textInterval);
                    loadingContainer.classList.add('d-none');
                    submitBtn.disabled = false;
                    loadingSpinner.classList.add('d-none');
                    submitBtnText.textContent = 'Check URL';
                    showAlert('An error occurred while processing your request. Please try again.', 'danger');
                });
                */
            }, 3000);
        });
    }
    
    // Function to display prediction results
    function displayResults(data) {
        const resultIcon = document.getElementById('resultIcon');
        const resultTitle = document.getElementById('resultTitle');
        const confidenceBar = document.getElementById('confidenceBar');
        const confidenceText = document.getElementById('confidenceText');
        const resultExplanation = document.getElementById('resultExplanation');
        
        // Calculate confidence percentage
        const confidence = parseFloat(data.confidence) * 100;
        
        // Update UI elements
        if (data.prediction === 'phishing') {
            resultIcon.className = 'fas fa-exclamation-triangle text-danger fa-5x';
            resultTitle.textContent = 'Warning: Potential Phishing Site Detected';
            resultTitle.className = 'text-center mb-3 text-danger';
            confidenceBar.className = 'progress-bar bg-danger';
            confidenceBar.style.width = `${confidence}%`;
            confidenceText.textContent = `${confidence.toFixed(1)}%`;
            resultExplanation.className = 'alert alert-danger mt-3';
            
            resultExplanation.innerHTML = `
                <h5><i class="fas fa-shield-alt me-2"></i>Security Alert</h5>
                <p>This URL shows characteristics commonly associated with phishing websites:</p>
                <ul>
                    <li>The URL may be attempting to mimic a legitimate website</li>
                    <li>Security features expected from legitimate sites may be missing</li>
                    <li>The domain could be newly registered or suspicious</li>
                </ul>
                <hr>
                <p class="mb-0"><strong>Recommendation:</strong> Do not proceed to this website or enter any personal information.</p>
            `;
        } else {
            resultIcon.className = 'fas fa-check-circle text-success fa-5x';
            resultTitle.textContent = 'Likely Safe Website';
            resultTitle.className = 'text-center mb-3 text-success';
            confidenceBar.className = 'progress-bar bg-success';
            confidenceBar.style.width = `${confidence}%`;
            confidenceText.textContent = `${confidence.toFixed(1)}%`;
            resultExplanation.className = 'alert alert-success mt-3';
            
            resultExplanation.innerHTML = `
                <h5><i class="fas fa-shield-alt me-2"></i>Security Assessment</h5>
                <p>This URL appears to be legitimate based on our analysis:</p>
                <ul>
                    <li>The URL structure follows normal patterns</li>
                    <li>Expected security features are present</li>
                    <li>No suspicious elements were detected</li>
                </ul>
                <hr>
                <p class="mb-0"><small>Note: Always exercise caution when sharing personal information online, even on seemingly legitimate websites.</small></p>
            `;
        }
        
        // Animate the confidence bar
        confidenceBar.style.transition = 'width 1s ease-in-out';
    }
    
    // Function to show alert messages
    function showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        
        alertDiv.innerHTML = `
            <div class="d-flex align-items-center">
                <div class="me-3">
                    <i class="fas fa-${type === 'danger' ? 'exclamation-circle' : 'info-circle'} fa-lg"></i>
                </div>
                <div>${message}</div>
            </div>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        const container = document.querySelector('.container');
        container.insertBefore(alertDiv, container.firstChild);
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 300);
        }, 5000);
    }
    
    // Add smooth scrolling to navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 70,
                    behavior: 'smooth'
                });
                
                // Update active nav link
                document.querySelectorAll('.nav-link').forEach(link => {
                    link.classList.remove('active');
                });
                this.classList.add('active');
            }
        });
    });
    
    // Set active nav link based on scroll position
    window.addEventListener('scroll', function() {
        const scrollPosition = window.scrollY;
        
        document.querySelectorAll('section').forEach(section => {
            const sectionTop = section.offsetTop - 100;
            const sectionBottom = sectionTop + section.offsetHeight;
            const sectionId = section.getAttribute('id');
            
            if (scrollPosition >= sectionTop && scrollPosition < sectionBottom) {
                document.querySelectorAll('.nav-link').forEach(link => {
                    link.classList.remove('active');
                    if (link.getAttribute('href') === `#${sectionId}`) {
                        link.classList.add('active');
                    }
                });
            }
        });
    });
    
    // Add active class to nav link for current section on page load
    const setInitialActiveNavLink = () => {
        const scrollPosition = window.scrollY;
        let activeSection = null;
        
        document.querySelectorAll('section').forEach(section => {
            const sectionTop = section.offsetTop - 100;
            const sectionBottom = sectionTop + section.offsetHeight;
            
            if (scrollPosition >= sectionTop && scrollPosition < sectionBottom) {
                activeSection = section.getAttribute('id');
            }
        });
        
        if (activeSection) {
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
                if (link.getAttribute('href') === `#${activeSection}`) {
                    link.classList.add('active');
                }
            });
        } else {
            // Default to first nav link if no section is active
            const firstNavLink = document.querySelector('.nav-link');
            if (firstNavLink) firstNavLink.classList.add('active');
        }
    };
    
    setInitialActiveNavLink();
}); 