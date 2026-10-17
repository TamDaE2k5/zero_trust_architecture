let token = null;
let sessionGeneration = 0;
const byId = id => document.getElementById(id);
byId('login').addEventListener('submit', async event => {
  event.preventDefault();
  const generation = ++sessionGeneration;
  token = null; byId('data').replaceChildren(); byId('evidence').textContent = '';
  try {
    const response = await fetch('/auth/login', {method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:byId('username').value,password:byId('password').value})});
    const result = await response.json();
    if (generation !== sessionGeneration) return;
    token = response.ok ? result.access_token : null;
    byId('session').textContent = response.ok ? `Đã đăng nhập: ${byId('username').value} · Phiên 10 phút` : 'Đăng nhập thất bại';
  } catch { if (generation === sessionGeneration) { token = null; byId('session').textContent = 'Không thể kết nối máy chủ'; } }
  byId('password').value = '';
});
byId('logout').addEventListener('click', async () => {
  const generation = ++sessionGeneration;
  const previous = token; token = null;
  byId('data').replaceChildren(); byId('evidence').textContent = '';
  try {
    const response = previous && await fetch('/auth/logout',{method:'POST',headers:{Authorization:`Bearer ${previous}`}});
    if (generation !== sessionGeneration) return;
    byId('session').textContent = !previous || response.ok ? 'Đã đăng xuất và thu hồi phiên' : 'Đã xóa phiên trên trang; máy chủ chưa xác nhận thu hồi';
  } catch { if (generation === sessionGeneration) byId('session').textContent = 'Đã xóa phiên trên trang; máy chủ chưa xác nhận thu hồi'; }
});
byId('read').addEventListener('click', async () => {
  byId('data').replaceChildren();
  if (!token) { byId('status').textContent = 'Bạn cần đăng nhập trước'; return; }
  const generation = sessionGeneration;
  byId('status').textContent = 'Đang kiểm tra quyền truy cập…';
  try {
    const response = await fetch(`/api/v1/data/${byId('resource').value}`,{headers:{Authorization:`Bearer ${token}`}});
    const result = await response.json();
    if (generation !== sessionGeneration) return;
    byId('status').textContent = response.ok ? `ĐƯỢC PHÉP · ${result.data.length} bản ghi` : `TỪ CHỐI · ${result.reason_code || result.detail || response.status}`;
    byId('status').className = response.ok ? 'allow' : 'deny';
    byId('evidence').textContent = JSON.stringify({...result,data:undefined},null,2);
    if (response.status === 401) token = null;
    if (response.ok && result.data.length) {
      const table = document.createElement('table');
      const columns = result.obligations.columns;
      const heading = document.createElement('tr');
      for (const column of columns) { const cell = document.createElement('th'); cell.textContent = column; heading.append(cell); }
      table.append(heading);
      for (const row of result.data) { const tr = document.createElement('tr');
        for (const column of columns) { const td = document.createElement('td'); td.textContent = row[column] ?? ''; tr.append(td); } table.append(tr); }
      byId('data').append(table);
    }
  } catch { if (generation === sessionGeneration) byId('status').textContent = 'Không thể xác minh quyền; không trả dữ liệu'; }
});
