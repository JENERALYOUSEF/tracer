document.addEventListener('DOMContentLoaded', function() {
    // Learning Category Selection
    const learningCategories = document.querySelectorAll('.learning-category');
    const learningContentContainer = document.getElementById('learning-content');
    const learningContentSections = document.querySelectorAll('.learning-content-section');

    learningCategories.forEach(category => {
        category.addEventListener('click', function() {
            // Show learning content container
            learningContentContainer.style.display = 'block';

            // Hide all content sections
            learningContentSections.forEach(section => {
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
});document.addEventListener('DOMContentLoaded', function() {
    // Learning Category Selection
    const learningCategories = document.querySelectorAll('.learning-category');
    const learningContentContainer = document.getElementById('learning-content');
    const learningContentSections = document.querySelectorAll('.learning-content-section');

    // Log to help debug
    console.log('Learning Categories:', learningCategories.ledocument.addEventListener('DOMContentLoaded', function() {
        // Learning Category Selection
        const learningCategories = document.querySelectorAll('.learning-category');
        const learningContentContainer = document.getElementById('learning-content');
        const learningContentSections = document.querySelectorAll('.learning-content-section');
    
        // Ensure all sections are hidden initially
        learningContentSections.forEach(section => {
            section.style.display = 'none';
        });
        learningContentContainer.style.display = 'none';
    
        // Add click event to each category
        learningCategories.forEach(category => {
            category.addEventListener('click', function() {
                // Show learning content container
                learningContentContainer.style.display = 'block';
    
                // Hide all content sections
                learningContentSections.forEach(section => {
                    section.style.display = 'none';
                });
    
                // Get the selected category
                const selectedCategory = this.getAttribute('data-category');
                
                // Show the selected category's content
                const selectedSection = document.getElementById(selectedCategory);
                if (selectedSection) {
                    selectedSection.style.display = 'block';
                    
                    // Scroll to content
                    selectedSection.scrollIntoView({ behavior: 'smooth' });
                } else {
                    console.error('No section found for category:', selectedCategory);
                }
            });
        });
    });ngth);
    console.log('Learning Content Container:', learningContentContainer);
    console.log('Learning Content Sections:', learningContentSections.length);

    learningCategories.forEach(category => {
        category.addEventListener('click', function() {
            // Show learning content container
            learningContentContainer.style.display = 'block';

            // Hide all content sections
            learningContentSections.forEach(section => {
                section.style.display = 'none';
            });

            // Get the selected category
            const selectedCategory = this.getAttribute('data-category');
            
            // Log selected category
            console.log('Selected Category:', selectedCategory);

            // Show the selected category's content
            const selectedSection = document.getElementById(selectedCategory);
            if (selectedSection) {
                selectedSection.style.display = 'block';
                
                // Optional: Scroll to content
                selectedSection.scrollIntoView({ behavior: 'smooth' });
            } else {
                console.error('No section found for category:', selectedCategory);
            }
        });
    });
});