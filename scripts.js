document.addEventListener('DOMContentLoaded', function() {
    const chatbox = document.getElementById('chatbox');
    if (chatbox) {
        chatbox.scrollTop = chatbox.scrollHeight;
    }
});