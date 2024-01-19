async function fetchDataAndPopulateTable() {
  try {
    const response = await fetch('/api/admin/users');
    const usersData = await response.json();

    populateTable(usersData);

    const currentUserResponse = await fetch('/api/user/info');
    const currentUserInfo = await currentUserResponse.json();

    aboutUser(currentUserInfo);
  } catch (error) {
    console.error('Error fetching data:', error);
  }
}

function populateTable(usersData) {
  const table = $('#usersTable')
    .find('tbody');
  table.empty();
  usersData.forEach((user) => {
    let rolesSHOW = '';
    user.roles.forEach((role) => {
      rolesSHOW += `<span>${role.name}</span> `;
    });

    const deleteButton = `
        <button type="button" class="btn btn-danger delete-btn" onclick="openDeleteModal(${user.id}, '${user.firstName}')" id="deletebtn">
        Delete
        </button> 
    `;

    const editButton = `
        <button type="button" class="btn btn-primary edit-btn" id="editbtn">
        Edit
        </button>
    `;
    table.append(`
      <tr>
        <td>${user.id}</td>
        <td>${user.firstName}</td>
        <td>${user.lastName}</td>
        <td>${user.age}</td>
        <td>${user.email}</td>
        <td>${rolesSHOW}</td>
        <td>${editButton}</td>
        <td>${deleteButton}</td>
      </tr>
    `);
  });
  $('.edit-btn')
    .click(function () {
      openEditModal($(this));
    });
}
function aboutUser(currentUserInfo) {
  const table = $('#aboutUser')
    .find('tbody');
  table.empty();

  let rolesSHOW = '';
  currentUserInfo.roles.forEach((role) => {
    rolesSHOW += `<span>${role.name}</span> `;
  });

  table.append(`
    <tr>
      <td>${currentUserInfo.id}</td>
      <td>${currentUserInfo.firstName}</td>
      <td>${currentUserInfo.lastName}</td>
      <td>${currentUserInfo.age}</td>
      <td>${currentUserInfo.email}</td>
      <td>${rolesSHOW}</td>
    </tr>
  `);
}

function openEditModal(editButton) {
  const userRow = editButton.closest('tr');
  const userData = {
    id: userRow.find('td:eq(0)').text(),
    firstName: userRow.find('td:eq(1)').text(),
    lastName: userRow.find('td:eq(2)').text(),
    age: userRow.find('td:eq(3)').text(),
    email: userRow.find('td:eq(4)').text(),
    roles: userRow.find('td:eq(5) span').map(function () {
      return $(this).text();
    })
      .get(),
  };

  const modalBody = $('#editModal .modal-body');
  modalBody.html(`
    <div class="form-group">
        <label for="edit_userid" class="form-label">ID</label>
        <input type="text" class="form-control" id="edit_userid" name="id" value="${userData.id}" readonly>
    </div>
    <div class="form-group">
        <label for="edit_firstname" class="form-label">First name</label>
        <input type="text" class="form-control" id="edit_firstname" name="firstName" value="${userData.firstName}">
    </div>
    <div class="form-group">
        <label for="edit_lastname" class="form-label">Last name</label>
        <input type="text" class="form-control" id="edit_lastname" name="lastName" value="${userData.lastName}">
    </div>
    <div class="form-group">
        <label for="edit_age" class="form-label">Age</label>
        <input type="number" class="form-control" id="edit_age" name="age" value="${userData.age}">
    </div>
    <div class="form-group">
        <label for="edit_email" class="form-label">Email</label>
        <input type="text" class="form-control" id="edit_email" name="email" value="${userData.email}">
    </div>
    <div class="form-group">
         <label for="edit_password" class="form-label">Password</label>
         <input type="password" class="form-control" id="edit_password" name="password" value="${userData.password}">
    </div>
    <div class="form-group">
        <label for="edit_roles" class="form-label">Roles</label>
    <select class="form-control" id="edit_roles" name="roles" size="2" multiple>
        <!-- Опция для заглушки -->
        <option value="" disabled selected>Select roles</option>
    </select>    </div>
    
`);

  const editForm = document.getElementById('editForm');

  editForm.addEventListener('submit', (event) => {
    event.preventDefault();
    editUser(event);
  });
  const editRolesSelect = document.getElementById('edit_roles');
  editRolesSelect.innerHTML = '<option value="" disabled selected>Loading roles...</option>';
  fetch('/api/admin/roles')
    .then((response) => response.json())
    .then((roles) => {
      editRolesSelect.innerHTML = '';
      roles.forEach((role) => {
        const option = document.createElement('option');
        option.value = role.id;
        option.text = role.name;
        editRolesSelect.appendChild(option);
      });
      const editModal = new bootstrap.Modal(document.getElementById('editModal'));
      editModal.show();
    })
    .catch((error) => {
      console.error('Error fetching roles:', error);
      editRolesSelect.innerHTML = '<option value="" disabled selected>Error loading roles</option>';
    });
}

function editUser(event) {
  event.preventDefault();

  const formData = new FormData(document.getElementById('editForm'));
  const userId = formData.get('id');
  const selectedRoles = Array.from(formData.getAll('roles'));
  const jsonData = {
    id: userId,
    age: Number(formData.get('age')),
    email: formData.get('email'),
    firstName: formData.get('firstName'),
    lastName: formData.get('lastName'),
    password: formData.get('password'),
    roles: selectedRoles,

  };

  fetch(`/api/admin/users/${userId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(jsonData),
  })
    .then((response) => {
      if (response.ok) {
        return fetchDataAndPopulateTable().then(() => {
          $('#editModal').modal('hide');
        });
      }
      console.error('Error editing user:', response.statusText);
      return Promise.reject(response.statusText);
    })
    .catch((error) => {
      console.error('Error editing user:', error);
    });
}
document.getElementById('saveChangesBtn').addEventListener('click', editUser);

// eslint-disable-next-line no-unused-vars
function openDeleteModal(userId, userName) {
  $('#userNameToDelete').text(userName);
  $('#deleteModal').modal('show');
  $('#confirmDeleteBtn').off('click').on('click', () => {
    deleteUserData(userId);
    $('#deleteModal').modal('hide');
  });
}
async function deleteUserData(userId) {
  try {
    const response = await fetch(`/api/admin/users/${userId}`, {
      method: 'DELETE',
    });

    if (response.ok) {
      fetchDataAndPopulateTable();
    } else {
      console.error('Error deleting user:', response.statusText);
    }
  } catch (error) {
    console.error('Error deleting user:', error);
  }
}
document.addEventListener('DOMContentLoaded', fetchDataAndPopulateTable);
