const formEl = document.querySelector('.form');

formEl.addEventListener('submit', event => {
  event.preventDefault();
  const formData = new FormData(formEl);
  const data = new URLSearchParams(formData);
  fetch('http://localhost:8080/login', {
    method: 'POST',
    body: data,
  }).then(res => {
    if (res.redirected) {
      console.log('Redirected to:', res.url);
      window.location.href = res.url;
      return;
    }
    if (!res.ok) {
      throw new Error(`Network response was not ok, status: ${res.status}`);
    }
    return res.json();
  }).then(data => console.log(data))
    .catch(error => console.error('Fetch error:', error));
});
