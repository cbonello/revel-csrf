revel-csrf
==========

`revel-csrf` implements Cross-Site Request Forgery (CSRF) attacks
prevention for the [Revel framework](https://github.com/revel/revel).

Code is based on the `nosurf` package implemented by
[Justinas Stankevičius](https://github.com/justinas/nosurf).

## Installation

    go get github.com/cbonello/revel-csrf

A demo application is provided in the samples directory. To launch it:

    revel run github.com/cbonello/revel-csrf/samples/demo

## Configuration options

Revel-csrf supports following configuration options in `app.conf`:

* `csrf.ajax`
A boolean value that indicates whether or not `revel-csrf` should support the injection and verification of CSRF tokens for XMLHttpRequests. Default value is `false`.

* `csrf.token.length`
An integer value that defines the number of characters that should be found within CSRF tokens. Token length should be in [32..512] and default value is 32 characters.

## Operating instructions

Simply call the CSRFFilter() filter in `app/init.go`.  

    package app

    import (
        "github.com/cbonello/revel-csrf"
        "github.com/revel/revel"
    )

    func init() {
	    // Filters is the default set of global filters.
	    revel.Filters = []revel.Filter{
		    revel.PanicFilter,             // Recover from panics and display an error page instead.
		    revel.RouterFilter,            // Use the routing table to select the right Action
		    revel.FilterConfiguringFilter, // A hook for adding or removing per-Action filters.
		    revel.ParamsFilter,            // Parse parameters into Controller.Params.
		    revel.SessionFilter,           // Restore and write the session cookie.
		    revel.FlashFilter,             // Restore and write the flash cookie.
		     csrf.CSRFFilter,              // CSRF prevention.
		    revel.ValidationFilter,        // Restore kept validation errors and save new ones from cookie.
		    revel.I18nFilter,              // Resolve the requested language
		    revel.InterceptorFilter,       // Run interceptors around the action.
		    revel.ActionInvoker,           // Invoke the action.
	    }
    }

Insert a hidden input field named `csrf_token` in your forms.

    <form action="/Hello" method="POST">
        <input type="text" name="name" />
        <input type="hidden" name="csrf_token" value="{{ .csrf_token }}" />
        <button type="submit">Send</button>
    </form>

Javascript-code sample to perform AJAX calls with jQuery 1.5 and newer. 

    function csrfSafeMethod(method) {
        // HTTP methods that do not require CSRF protection.
        return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
    $.ajaxSetup({
        crossDomain: false,
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type)) {
                xhr.setRequestHeader("X-CSRF-Token", {{ .csrf_token }});
            }
        }
    });

	$("#AJAXForm").submit(function(event){
		event.preventDefault();
	    $.ajax({
	        type: "POST",
	        url: "/Hello",
	        data: {
	            name: $("#AJAXFormName").val()
	        },
	        success: function(data) {
	            // Switch to HTML code returned by server on success.
	            jQuery("body").html(data);
	        },
	        error: function(jqXHR, status, errorThrown) {
	            alert(jqXHR.statusText);
	        },
	    });
	});

You can call `csrf.ExemptedFullPath()` or `csrf.ExemptedGlob()` to exempt routes from CSRF checks. See `app/init.go` in demo application.

## TODO

* Unique token per-page.
* Test cases.

## CONTRIBUTORS
* Otto Bretz
* Allen Dang
