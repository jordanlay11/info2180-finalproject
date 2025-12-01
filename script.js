document.addEventListener('DOMContentLoaded', () => {
    const sections = document.querySelectorAll('section');
    
    const showSection = (hash) => {
        sections.forEach(s => s.style.display = 'none');
        const target = document.getElementById(hash.slice(1));
        if (target) target.style.display = 'block';
    };

    showSection(window.location.hash || '#home');

    document.querySelectorAll('nav li a').forEach(link =>
        link.addEventListener('click', () => {
            const hash = link.getAttribute('href');
            showSection(hash);
            window.location.hash = hash;
        })
    );

    window.addEventListener('hashchange', () => showSection(window.location.hash || '#home'));
});