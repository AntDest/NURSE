function createFilterList(list_devices) {   
    var ul_devices = document.getElementById("device_filter_list");
    for (i = 0; i < list_devices.length; i++) {
        var li = document.createElement("li");
        li.innerHTML = "<label><input type=\"checkbox\" checked onchange=\"filterTable()\"></input>" + list_devices[i] + "</label>";
        ul_devices.appendChild(li);
    }
}

// called when (un)checking a box in the filter list on top
function filterTable() {
    let allowed_devices = [];
    var ul_devices = document.getElementById("device_filter_list");
    let list_li = ul_devices.getElementsByTagName("li");
    for (let i = 0; i < list_li.length; i++) {
        const li = list_li[i];
        let box = li.getElementsByTagName("input")[0];
        if (box.checked) {
            allowed_devices.push(li.innerText);
        }
    }
    // allowed_devices now contains the list of devices we want to keep
    let table = document.getElementById("domain_list");
    tr = table.getElementsByTagName("tr");
    // Loop through all table rows, and hide those who don't match the allowed_devices
    for (i = 0; i < tr.length; i++) {
        td = tr[i].getElementsByTagName("td")[0];
        if (td) {
            txtValue = td.textContent || td.innerText;
            if (allowed_devices.includes(txtValue)) {
                tr[i].style.display = "";
            } else {
                tr[i].style.display = "none";
            }
        } 
    }
}