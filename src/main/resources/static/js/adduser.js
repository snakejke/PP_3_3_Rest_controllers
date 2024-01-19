document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('nav-adduser-form');

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    const formData = new FormData(form);
    const selectedRoles = formData.getAll('role');

    const jsonData = {
      age: Number(formData.get('age')),
      email: formData.get('email'),
      firstName: formData.get('firstName'),
      lastName: formData.get('lastName'),
      password: formData.get('password'),
      roles: selectedRoles.map((roleId) => ({ id: roleId })),
    };

    // Отправляем запрос на сервер для создания пользователя
    const createUserResponse = await fetch('/api/admin/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(jsonData),
    });

    if (createUserResponse.ok) {
      const usersWithRoles = await fetch('/api/admin/users').then((response) => response.json());
      console.log('User created successfully:', usersWithRoles);
      fetchDataAndPopulateTable();
    } else {
      console.error('Error creating user:', createUserResponse.statusText);
    }
  });
});
