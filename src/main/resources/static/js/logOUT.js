const logoutForm = document.querySelector('#logoutForm');
logoutForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const res = await fetch('http://localhost:8080/logout', { method: 'POST' });
    if (res.ok) {
      window.location.href = '/';
    } else {
      console.error('Logout failed:', res.status);
    }
  } catch (error) {
    console.error('Fetch error:', error);
  }
});
