async function fetchUsers() {
  try {
    const currentUserResponse = await fetch('/api/user/info');
    return await currentUserResponse.json();
  } catch (error) {
    console.error('Error fetching user', error);
    throw error;
  }
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
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const users = await fetchUsers();
    aboutUser(users);
  } catch (error) {
    console.error(error);
  }
});
