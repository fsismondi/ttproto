var baseUrl = 'http://127.0.0.1:8080';

/**
 * Function to get the test cases
 */
function getTestCases() {

	var url = baseUrl + '/finterop/get_testcases';

	// Remove the get test cases button
	$('#get-tc-button').remove();

	// Replace it by a loading button
	$('#button-bloc').append('<button class="btn btn-warning"><span class="glyphicon glyphicon-refresh spinning"></span> Loading...</button>');

	// Send the post request in ajax
	$.ajax({
		url: url,
		type: 'GET',
		dataType: 'json',
		success: function(input) {

			// Correct response
			if (input.ok == true && input._type == 'response')  {

				// Display the list of test cases
				for (var tc in input.content) {
					$('#test-cases').append(
						'<li class="list-group-item" id="' + input.content[tc].id + '">\
							<h4 class="list-group-item-heading">' + input.content[tc].id + '</h4>\
							<p class="list-group-item-text">' + input.content[tc].objective + '</p>\
						</li>\
					');
				}

				// Display the state						
				$('#console').append('<div class="alert alert-info alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>' + input.content.length + ' test cases loaded</div>');

				// Hide loading button
				$('.btn-warning').remove();

				// Put the start ts button
				$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="startTestSuite()" id="start-ts-button" >Start Test Suite</button>');
			

			// If we have an error
			} else {

				// Display the error message
				$('#console').append('<div class="alert alert-danger alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>' + input.error + '</div>');

				// Hide loading button
				$('.btn-warning').remove();

				// Put back the button
				$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="getTestCases()" id="get-tc-button" >Get Test Cases</button>');
			}
		},
		error: function(xhr, status, err) {
			console.error(url, status, err.toString());

			// Display the error message
			$('#console').append('<div class="alert alert-danger alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>No response from the API</div>');

			// Hide loading button
			$('.btn-warning').remove();

			// Put back the button
			$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="getTestCases()" id="get-tc-button" >Get Test Cases</button>');
		}
	});
}


/**
 * Function to start the test suite
 */
function startTestSuite() {

	var url = baseUrl + '/finterop/start_test_suite';

	// Hide the start button
	$('#start-ts-button').remove();

	// Replace it by a loading button
	$('#button-bloc').append('<button class="btn btn-warning"><span class="glyphicon glyphicon-refresh spinning"></span> Loading...</button>');

	// Send the post request in ajax
	$.ajax({
		url: url,
		type: 'GET',
		dataType: 'json',
		success: function(input) {

			// Correct response
			if (input.ok == true && input._type == 'response')  {

				// Parse the response
				for (var inp in input.content) {

					// Display the message if there's one
					if (input.content[inp]._type == 'message')
						$('#console').append('<div class="alert alert-info alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>' + input.content[inp].message + '</div>');

					// Put the first TC if there's one
					if (input.content[inp]._type == 'tc_basic')
						$('#' + input.content[inp].id).attr('class', $('#' + input.content[inp].id).attr('class') + ' active');
				}

				// Hide loading button
				$('.btn-warning').remove();

				// Put the start tc button
				$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="startTestCase()" id="start-tc-button" >Start Test Case</button>');


			// If we have an error
			} else {

				// Display the error message
				$('#console').append('<div class="alert alert-danger alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>' + input.error + '</div>');

				// Hide loading button
				$('.btn-warning').remove();

				// Put back the button
				$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="startTestSuite()" id="start-ts-button" >Start Test Suite</button>');
			}
		},
		error: function(xhr, status, err) {
			console.error(url, status, err.toString());

			// Display the error message
			$('#console').append('<div class="alert alert-danger alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>No response from the API</div>');

			// Hide loading button
			$('.btn-warning').remove();

			// Put back the button
			$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="startTestSuite()" id="start-ts-button" >Start Test Suite</button>');
		}
	});
}


/**
 * Function to start the test case
 */
function startTestCase() {

	var url = baseUrl + '/finterop/start_test_case';

	// Hide the start test case button
	$('#start-tc-button').remove();

	// Replace it by a loading button
	$('#button-bloc').append('<button class="btn btn-warning"><span class="glyphicon glyphicon-refresh spinning"></span> Loading...</button>');

	// Send the post request in ajax
	$.ajax({
		url: url,
		type: 'POST',
		dataType: 'json',
		data: {'testcase_id': $('#test-cases .active').attr('id')},
		success: function(input) {

			// Correct response
			if (input.ok == true && input._type == 'response')  {

				// Parse the response
				for (var inp in input.content) {

					// Just display the message
					if (input.content[inp]._type == 'message')
						$('#console').append('<div class="alert alert-info" role="alert">' + input.content[inp].message + '</div>');
				}

				// Hide loading button
				$('.btn-warning').remove();

				// Put the finish tc button
				$('#button-bloc').append('<button class="btn btn-danger centered-block" onClick="finishTestCase()" id="finish-tc-button" >Finish Test Case</button>');


			// If we have an error
			} else {

				// Display the error message
				$('#console').append('<div class="alert alert-danger alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>' + input.error + '</div>');

				// Hide loading button
				$('.btn-warning').remove();

				// Put back the button
				$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="startTestCase()" id="start-tc-button" >Start Test Case</button>');
			}
		},
		error: function(xhr, status, err) {
			console.error(url, status, err.toString());

			// Display the error message
			$('#console').append('<div class="alert alert-danger alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>No response from the API</div>');

			// Hide loading button
			$('.btn-warning').remove();

			// Put back the button
			$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="startTestCase()" id="start-tc-button" >Start Test Case</button>');
		}
	});
}


/**
 * Function to finish the test case
 */
function finishTestCase() {

	var url = baseUrl + '/finterop/finish_test_case';

	// Remove the finish button
	$('#finish-tc-button').remove();

	// Replace it by a loading button
	$('#button-bloc').append('<button class="btn btn-warning"><span class="glyphicon glyphicon-refresh spinning"></span> Loading...</button>');

	// Send the post request in ajax
	$.ajax({
		url: url,
		type: 'POST',
		dataType: 'json',
		data: {'testcase_id': $('#test-cases .active').attr('id')},
		success: function(input) {

			// Correct response
			if (input.ok == true && input._type == 'response') {

				// Parse the response
				var moreTestCase = true;
				for (var inp in input.content) {

					// Just display the message
					if (input.content[inp]._type == 'message')
						$('#console').append('<div class="alert alert-info" role="alert">' + input.content[inp].message + '</div>');

					// If verdict, give it
					if (input.content[inp]._type == 'verdict')
						$('#console').append(
							'<div class="alert alert-success" role="alert">'
							+ input.content[inp].description
							+ ' gave the verdict '
							+ input.content[inp].verdict
							+ '</div>'
						);

					// Check if there's a next test case to display
					if (input.content[inp]._type == 'information')
						moreTestCase = (input.content[inp].last_test_case == false);

					// The next case to display if it's not the last
					if (input.content[inp]._type == 'tc_basic')
						var nextTestCase = input.content[inp].id;

				}

				// If there's a next test case to execute
				if (moreTestCase) {
					$('#test-cases .active').attr('class', 'list-group-item');
					console.log(nextTestCase);
					$('#' + nextTestCase).attr('class', $('#' + nextTestCase).attr('class') + ' active');
				}

				// Hide loading button
				$('.btn-warning').remove();

				// Put the start tc button for the next test case
				$('#button-bloc').append('<button class="btn btn-success centered-block" onClick="startTestCase()" id="start-tc-button" >Start Test Case</button>');


			// If we have an error
			} else {

				// Display the error message
				$('#console').append('<div class="alert alert-danger alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>' + input.error + '</div>');

				// Hide loading button
				$('.btn-warning').remove();
				
				// Put back the button
				$('#button-bloc').append('<button class="btn btn-danger centered-block" onClick="finishTestCase()" id="finish-tc-button" >Finish Test Case</button>');
			}
		},
		error: function(xhr, status, err) {
			console.error(url, status, err.toString());

			// Display the error message
			$('#console').append('<div class="alert alert-danger alert-dismissible" role="alert"><button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>No response from the API</div>');

			// Hide loading button
			$('.btn-warning').remove();
			
			// Put back the button
			$('#button-bloc').append('<button class="btn btn-danger centered-block" onClick="finishTestCase()" id="finish-tc-button" >Finish Test Case</button>');
		}
	});
}