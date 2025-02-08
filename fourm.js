document.addEventListener('DOMContentLoaded', function() {
    const newTopicForm = document.querySelector('#newTopicModal form');
    
    if (newTopicForm) {
        newTopicForm.addEventListener('submit', function(event) {
            event.preventDefault();
            
            const topicTitle = this.querySelector('input[type="text"]').value;
            const topicCategory = this.querySelector('select').value;
            const topicMessage = this.querySelector('textarea').value;

            if (topicTitle && topicCategory !== 'Select Category' && topicMessage) {
                // Here you would typically send this data to a backend
                console.log('New Topic:', { 
                    title: topicTitle, 
                    category: topicCategory, 
                    message: topicMessage 
                });
                
                // Show success message
                alert('Topic created successfully!');
                
                // Close modal
                const modalElement = document.getElementById('newTopicModal');
                const modalInstance = bootstrap.Modal.getInstance(modalElement);
                if (modalInstance) {
                    modalInstance.hide();
                }

                // Reset form
                this.reset();
            } else {
                alert('Please fill in all fields');
            }
        });
    } else {
        console.error('New topic form not found');
    }

    // Forum Category Selection
    const forumCategories = document.querySelectorAll('.forum-category');
    const forumContentContainer = document.getElementById('forum-content');
    const forumContentSections = document.querySelectorAll('.forum-content-section');

    forumCategories.forEach(category => {
        category.addEventListener('click', function() {
            // Show forum content container
            forumContentContainer.style.display = 'block';

            // Hide all content sections
            forumContentSections.forEach(section => {
                section.style.display = 'none';
            });

            // Get the selected category
            const selectedCategory = this.getAttribute('data-category');
            
            // Show the selected category's content
            const selectedSection = document.getElementById(selectedCategory);
            if (selectedSection) {
                selectedSection.style.display = 'block';
            }

            // Optional: Scroll to content
            selectedSection.scrollIntoView({ behavior: 'smooth' });
        });
    });

    // Chat Input Handling
    const chatForms = document.querySelectorAll('.chat-input');
    
    chatForms.forEach(form => {
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            
            const input = this.querySelector('input');
            const message = input.value.trim();
            
            if (message) {
                // Create new message element
                const messagesContainer = this.closest('.card').querySelector('.chat-messages');
                const newMessage = document.createElement('div');
                newMessage.classList.add('message');
                newMessage.innerHTML = `
                    <strong class="text-cyber-accent">@You:</strong> 
                    ${message}
                `;
                
                // Add message to chat
                messagesContainer.appendChild(newMessage);
                
                // Clear input
                input.value = '';
                
                // Optional: Scroll to bottom of messages
                messagesContainer.scrollTop = messagesContainer.scrollHeight;
            }
        });
    });
});