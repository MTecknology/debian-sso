$(document).ready(function() {
  $('#registerform').on('submit', function(e) {
    e.preventDefault();
    $.ajax({
      url: $(this).attr('action'),
      type: 'POST',
      data: $(this).serialize(),
      dataType: "json",
      success: function (data) {
        if(data.result == 1) {
          window.location.replace('/');
        } else {
          $('#token').val(data.token);
          $('#msg').html(data.error);
          $('#msg').removeClass('alert-success').addClass('alert-danger');
        }
      },
      error: function (jXHR, textStatus, errorThrown) {
        alert(errorThrown);
      }
    });
    return false;
  });
});
