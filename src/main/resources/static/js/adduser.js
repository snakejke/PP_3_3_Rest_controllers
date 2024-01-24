document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('nav-adduser-form');
  const usertableTab = document.getElementById('nav-home-tab');

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

    try {
      const createUserResponse = await fetch('/api/admin/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(jsonData),
      });

      if (createUserResponse.ok) {
        form.reset();
        usertableTab.click();
        fetchDataAndPopulateTable();
      } else {
        console.error('Error creating user:', createUserResponse.statusText);
      }
    } catch (error) {
      console.error('Error creating user:', error);
    }
  });
});
