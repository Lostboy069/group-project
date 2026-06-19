document.addEventListener('DOMContentLoaded', () => {
    console.log('Cyber Shield AI Initialized');

    const revealTargets = document.querySelectorAll('.team-card');

    if (revealTargets.length) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.15 });

        revealTargets.forEach((el) => observer.observe(el));
    }
});