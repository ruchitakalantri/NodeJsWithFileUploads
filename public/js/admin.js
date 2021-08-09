//not on server .. run on client side .. browser

const deleteProduct = (btn) => {
    const prodId = btn.parentNode.querySelector('[name= productId').value ;
    const csrf = btn.parentNode.querySelector('[name= _csrf').value ;
    console.log('prodId : ' + prodId);
    console.log('csrf token : ' + csrf);

    // send http request 
    fetch('/admin/product/' + prodId , {
        method : 'DELETE' ,
        headers : {
            'csrf-token' : csrf
        }
    })
    .then(result => {
        console.log(result);
    })
    .catch(err => {
        console.log(err);
    });

};