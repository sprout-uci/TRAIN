document.addEventListener('DOMContentLoaded', function() {
    // Current time step (0 = t₀, 1 = t₁, etc.)
    let currentStep = 0;
    const maxStep = 7;

    // Elements that will be updated
    const nextButton = document.getElementById('next-button');
    const resetButton = document.getElementById('reset-button');
    const currentTimeLabel = document.getElementById('current-time');
    const timeMarkers = document.querySelectorAll('.time-marker');
    const timeLines = document.querySelectorAll('.time-line');
    
    // Get all the state bars
    const deviceAPendingBar = document.querySelector('.device-a .state-bar[data-time="0"]');
    const deviceASecureBar = document.querySelector('.device-a .state-bar[data-time="1"]');
    const deviceACompromisedBar = document.querySelector('.device-a .state-bar[data-time="2"]');
    const deviceBPendingBar = document.querySelector('.device-b .state-bar[data-time="0"]');
    const deviceBSecureBar = document.querySelector('.device-b .state-bar[data-time="3"]');
    
    // Elements that will appear at different steps
    const elements = {
        // t₀: Verifier sends request
        0: [
            { id: 'verifier-request', element: document.querySelector('.event[data-time="0"]') }
        ],
        // t₁: Device A attests
        1: [
            { id: 'device-a-attest', element: document.querySelector('.event[data-time="1"]') },
            { id: 'toctou-start', element: document.querySelector('.toctouna-window-start') },
            { id: 'toctou-highlight-start', element: document.querySelector('.toctou-highlight-start') }
        ],
        // t₂: No changes
        2: [ { id: 'verifier-receive-a', element: document.querySelector('.event[data-time="2-verifier"]') }],
        // t₃: Device A becomes compromised, Verifier receives A’s report
        3: [
            { id: 'device-a-compromised', element: document.querySelector('.event[data-time="3"]') },
            { id: 'verifier-receive-a', element: document.querySelector('.event[data-time="2-verifier"]') }
        ],
        // t₄: Device B attests
        4: [
            { id: 'device-b-attest', element: document.querySelector('.event[data-time="4"]') }
        ],
        // t₅: Verifier receives B’s report, makes erroneous conclusion
        5: [
            { id: 'verifier-receive-b', element: document.querySelector('.event[data-time="5"]') }
        ],
        6: [
            { id: 'verifier-warning', element: document.querySelector('.warning') },
            { id: 'toctou-complete', element: document.querySelector('.toctouna-window-complete') },
            { id: 'toctou-highlight-complete', element: document.querySelector('.toctou-highlight-complete') }
        ]
    };

    // Initialize all state bars with width 0
    deviceAPendingBar.style.width = '0';
    deviceASecureBar.style.width = '0';
    deviceACompromisedBar.style.width = '0';
    deviceBPendingBar.style.width = '0';
    deviceBSecureBar.style.width = '0';

    // Hide all elements initially
    for (let step = 0; step <= maxStep; step++) {
        if (elements[step]) {
            elements[step].forEach(item => {
                if (item.element) {
                    item.element.classList.add('hidden');
                }
            });
        }
    }
    
    // Only show the first time marker initially
    timeMarkers.forEach((marker, index) => {
        if (index > 0) {
            marker.classList.add('hidden');
        }
    });
    
    timeLines.forEach((line, index) => {
        if (index > 0) {
            line.classList.add('hidden');
        }
    });

    // Update current time display
    updateTimeDisplay();

    // Next button click handler
    nextButton.addEventListener('click', function() {
        if (currentStep < maxStep) {
            currentStep++;
            updateVisualization();
        }
    });

    // Reset button click handler
    resetButton.addEventListener('click', function() {
        currentStep = 0;
        resetVisualization();
    });

    // Update the visualization based on current step
    function updateVisualization() {
        // Show time marker for current step
        if (currentStep < timeMarkers.length) {
            timeMarkers[currentStep].classList.remove('hidden');
        }
        if (currentStep < timeLines.length) {
            timeLines[currentStep].classList.remove('hidden');
        }
        
        // Show elements for current step
        if (elements[currentStep]) {
            elements[currentStep].forEach(item => {
                if (item.element) {
                    item.element.classList.remove('hidden');
                }
            });
        }
        if (currentStep === 6) {
            const receiveB = document.querySelector('.event[data-time="5"]');
            if (receiveB) receiveB.classList.add('hidden');
        }
        // Show TOCTOU label only from t₂ and beyond
const toctouLabel = document.querySelector('.toctou-label');
if (currentStep >= 2) {
    toctouLabel.classList.remove('hidden');
} else {
    toctouLabel.classList.add('hidden');
}
        
        // Update TOCTOUNA window width
        updateToctounaWindow();
        
        // Update device state bars
        updateStateBarWidths();
        
        // Update current time display
        updateTimeDisplay();
        
        // Disable next button at max step
        if (currentStep >= maxStep) {
            nextButton.disabled = true;
        }
    }

    // Reset the visualization to initial state
    function resetVisualization() {
        // Hide all elements
        for (let step = 0; step <= maxStep; step++) {
            if (elements[step]) {
                elements[step].forEach(item => {
                    if (item.element) {
                        item.element.classList.add('hidden');
                    }
                });
            }
        }
        
        // Show only first time marker
        timeMarkers.forEach((marker, index) => {
            if (index > 0) {
                marker.classList.add('hidden');
            } else {
                marker.classList.remove('hidden');
            }
        });
        
        timeLines.forEach((line, index) => {
            if (index > 0) {
                line.classList.add('hidden');
            } else {
                line.classList.remove('hidden');
            }
        });
        
        // Show initial elements at t₀
        if (elements[0]) {
            elements[0].forEach(item => {
                if (item.element) {
                    item.element.classList.remove('hidden');
                }
            });
        }
        
        // Reset TOCTOUNA window
        document.querySelector('.toctouna-window').style.width = '0';
        document.querySelector('.toctou-highlight').style.width = '0';
        
        // Reset all state bars
        deviceAPendingBar.style.width = '0';
        deviceASecureBar.style.width = '0';
        deviceACompromisedBar.style.width = '0';
        deviceBPendingBar.style.width = '0';
        deviceBSecureBar.style.width = '0';
        
        // Reset current time display
        currentStep = 0;
        updateTimeDisplay();
        
        // Enable next button
        nextButton.disabled = false;
    }

    // Update the width of the TOCTOUNA window
    function updateToctounaWindow() {
        const toctounaWindow = document.querySelector('.toctouna-window');
        const toctouHighlight = document.querySelector('.toctou-highlight');
    
        if (currentStep >= 1) {
            // It starts at t₁, and should grow only through t₅
            const visibleStep = Math.min(currentStep, 5); // cap at t₅
            const width = (visibleStep - 1) * 16.67;
            toctounaWindow.style.width = width + '%';
            toctouHighlight.style.width = width + '%';
        } else {
            toctounaWindow.style.width = '0';
            toctouHighlight.style.width = '0';
        }
    }

    function updateStateBarWidths() {
        // Reset all widths
        deviceAPendingBar.style.width = '0';
        deviceASecureBar.style.width = '0';
        deviceACompromisedBar.style.width = '0';
        deviceBPendingBar.style.width = '0';
        deviceBSecureBar.style.width = '0';
    
        // Device A
        if (currentStep >= 1) {
            deviceAPendingBar.style.width = '16.67%'; // t₀→t₁
        }
        if (currentStep >= 2) {
            deviceASecureBar.style.width = '16.67%'; // t₁→t₂
        }
        if (currentStep >= 3) {
            deviceASecureBar.style.width = '33.34%'; // t₂→t₃
        }
        if (currentStep >= 4) {
            deviceACompromisedBar.style.width = '16.67%'; // t₂→t₄
        }
        if (currentStep >= 5) {
            deviceACompromisedBar.style.width = '33.34%'; // t₂→t₅
        }
    
        // Device B
        if (currentStep >= 1) {
            deviceBPendingBar.style.width = '16.67%'; // t₀→t₁
        }
        if (currentStep >= 2) {
            deviceBPendingBar.style.width = '33.34%'; // t₁→t₂
        }
        if (currentStep >= 3) {
            deviceBPendingBar.style.width = '50%'; // t₂→t₃
        }
        if (currentStep >= 4) {
            deviceBPendingBar.style.width = '66.67%'; // t₃→t₄
        }
        if (currentStep >= 5) {
            deviceBSecureBar.style.width = '16.67%'; // t₄→t₅
        }
    }

    // Update the current time display
    function updateTimeDisplay() {
        currentTimeLabel.innerHTML = `t<sub>${currentStep}</sub>`;
    }

    // Start with t₀ elements visible
    elements[0].forEach(item => {
        if (item.element) {
            item.element.classList.remove('hidden');
        }
    });
});