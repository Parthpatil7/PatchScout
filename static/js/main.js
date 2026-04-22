// PatchScout - Custom JavaScript

$(document).ready(function() {
    // Mobile Sidebar Toggle
    $('#mobileSidebarToggle, #sidebarToggle').on('click', function() {
        $('.sidebar').toggleClass('active');
        $('.sidebar-overlay').toggleClass('active');
    });
    
    $('#sidebarOverlay').on('click', function() {
        $('.sidebar').removeClass('active');
        $(this).removeClass('active');
    });
    
    // Smooth scroll
    $('a[href^="#"]').on('click', function(e) {
        const target = $(this.getAttribute('href'));
        if (target.length) {
            e.preventDefault();
            $('html, body').animate({
                scrollTop: target.offset().top - 100
            }, 500);
        }
    });
    
    // Auto-hide alerts
    setTimeout(function() {
        $('.alert').fadeOut('slow');
    }, 5000);
    
    // Add fade-in animation to cards
    $('.card, .stat-card').each(function(i) {
        $(this).css('animation-delay', (i * 0.1) + 's').addClass('fade-in');
    });
});

// Toast notifications
function showToast(message, type = 'info') {
    const bgClass = {
        'success': 'bg-success',
        'danger': 'bg-danger',
        'warning': 'bg-warning',
        'info': 'bg-info'
    }[type] || 'bg-info';
    
    const toast = `
        <div class="toast align-items-center text-white ${bgClass} border-0" role="alert" style="position: fixed; bottom: 20px; right: 20px; z-index: 9999;">
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    
    $('body').append(toast);
    const toastEl = $('.toast').last()[0];
    const bsToast = new bootstrap.Toast(toastEl);
    bsToast.show();
    
    setTimeout(() => $(toastEl).remove(), 5000);
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    });
}

// Confirm dialog
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}
