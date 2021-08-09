//not on server .. run on client side .. browser

const deleteProduct = (btn) => {
    const prodId = btn.parentNode.querySelector('[name= productId').value ;
    const csrf = btn.parentNode.querySelector('[name= _csrf').value ;
    console.log('prodId : ' + prodId);
    console.log('csrf token : ' + csrf);

    const productElement = btn.closest('article');

    // send http request 
    fetch('/admin/product/' + prodId , {
        method : 'DELETE' ,
        headers : {
            'csrf-token' : csrf
        }
    })
    .then(result => {
        return result.json();
    })
    .then(data => {
        console.log(data);
        productElement.parentNode.removeChild(productElement);
    })
    .catch(err => {
        console.log(err);
    });

};