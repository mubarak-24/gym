document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const form = e.target;
  const formData = new FormData(form);

  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Accept': 'text/html' },   // we expect an HTML redirect
    body: new URLSearchParams(formData)
  });

  // Flask will respond with a redirect to /dashboard
  if (res.redirected) {
    window.location.href = res.url;
    return;
  }

  if (res.ok) {
    // fallback, just in case
    window.location.href = '/dashboard';
  } else {
    document.getElementById('loginMsg').textContent = 'Invalid username or password';
  }
});