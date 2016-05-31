// ############### Some parameters ###############

// Some constant values
var baseUrl = 'http://127.0.0.1:2080';
var acceptedActions = ['analyse', 'dissect'];

// Urls of the API
var dissectUrl = '/api/v1/frames_dissect';
var getFrameUrl = '/api/v1/frames_getFrame';
var getProtocolsUrl = '/api/v1/frames_getProtocols';
var analyseUrl = '/api/v1/testcase_analyse';
var getTestCasesUrl = '/api/v1/testcase_getList';
var getTestCaseImplementation = '/api/v1/testcase_getTestcaseImplementation';



// ############### Utility functions ###############
function checkError(errorTrigger, data) {

	// Check the datas received
	if (data && data._type == 'response') {

		// Check that there's an error to display
		if (!data.ok) {

			// Clear the error message displayer
			$('#error-modal .modal-body .alert').html(
				'<button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>'
			);

			// The error message to display
			var errorMessage = 'An error occured';

			// Check if we have the error trigger
			if (errorTrigger != '') errorMessage += ' during ' + errorTrigger;

			// Check the data we have
			if (data.error != '') errorMessage += '<br/><br/>More informations:</br>' + data.error;
			
			// Display the error itself in a bootstrap model
			$('#error-modal .modal-body .alert').append(errorMessage);
			$('#error-modal').modal('show');
		}

	// Wrong values passed
	} else console.log('WARNING: The data passed for the checking isn\'t a correct response');
}


// ############### React code ###############

// A renderer for the radio buttons
var RadioButton = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {
		var selected = (this.props.currentAction == this.props.inputValue);
		return (
			<label className={ (selected) ? 'btn btn-info active' : 'btn btn-info' } onClick={this.props.switchAction} value={this.props.inputValue} >
				<input type="radio" checked={selected} id={this.props.inputValue} name={this.props.inputName} value={this.props.inputValue} onChange={function(){}} /> {this.props.inputText}
			</label>
		);
	}
});



// A renderer for the input groups
var InputGroupBloc = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// Prepare the addon part
		var addonPart = <span className="input-group-addon">{this.props.addonText}</span>;

		// Return the input group with the text on the left or on the right
		return (
			<div className="input-group">
				{ (this.props.textOnLeft) ? addonPart : null }
				<input id={this.props.inputName} type={this.props.inputType} readOnly={this.props.readOnly} className="form-control" name={this.props.inputName} placeholder={this.props.inputPlaceholder} required={this.props.required} onChange={this.props.onChange} />
				{ (this.props.textOnLeft) ? null : addonPart }
			</div>
		);
	}
});



// A renderer for the select group
var SelectGroupBloc = React.createClass({

	/**
	 * Map the option group received
	 */
	mapOptionGroups: function(o) {

		// Analyse function
		if ((this.props.currentAction == 'analyse') && (o._type == 'tc_basic'))
			return (
				<option key={o.id} value={o.id} title={o.objective} >{o.id}</option>
			);

		// Dissect function
		else if (o._type == 'protocol')
			return (
				<option key={o.name} value={o.name} title={o.description} >{o.name}</option>
			);

		// Error if not entered into the previous returns
		console.log('WARNING: Wrong type ' + o._type + ' for the select group');
		return null;
	},


	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// Analyse action
		if (this.props.currentAction == 'analyse') {
			var optionInputName = 'testcase_id';
			var optionAddonText = 'Test case';

		// Dissect action
		} else {
			var optionInputName = 'protocol_selection';
			var optionAddonText = 'Protocol';
		}

		// Check the result
		if (this.props.optionGroups && this.props.optionGroups._type == 'response' && this.props.optionGroups.ok) {
			return (
				<div className="input-group">
					<span className="input-group-addon" >{optionAddonText}</span>
					<select name={optionInputName} className="form-control">
						{ this.props.optionGroups.content.map(this.mapOptionGroups) }
					</select>
				</div>
			);

		// An error occured
		} else if (typeof this.props.optionGroups === 'object') {
			console.log('WARNING: Couldn\'t retrieve ' + optionInputName);
			if (this.props.optionGroups && this.props.optionGroups._type == 'error' && !this.props.optionGroups.ok)
				console.log('More informations: ' + this.props.optionGroups.value);
		}
		return null;
	}
});



// The FormBloc renderer
var FormBloc = React.createClass({

	/**
	 * A token manager to manage the current token
	 */
	tokenManager(response) {

		// Check that it's a response
		if (response && response._type == 'response') {

			// Check that it's correct
			if (response.ok && response.content) {

				// Get the token of the packet
				var newToken = false;
				var i = 0;
				while (!newToken) {

					// No token found in the response
					if (i == response.content.length) {
						console.log('WARNING: Token manager received a response which doesn\'t contain a token');
						return;
					}

					// Parse the values util the token is found
					if (response.content[i]._type == 'token') newToken = response.content[i].value;
					i++;
				}

				// If no token for the moment
				if (!this.state.token) {

					// Update the current token
					this.setState({token: newToken});

					// Remove the current pcap file
					this.setState({pcapFile: false});
				
				// If there's already a token, check that the values correspond!
				} else if (this.state.token != newToken) console.log('WARNING: Token manager received a token that doesn\'t correspond to the current one');
			}

		// Incorrect data
		} else console.log('WARNING: Token manager received incorrect response data');
	},


	/**
	 * Handler for the submit of the form
	 */
	handlePcapSubmit: function(form) {

		// Bloc the "real" submit of the form, instead use this function
		form.stopPropagation();
		form.preventDefault();

		// Get the url
		var url = form.currentTarget.action;

		// Prepare the post datas
		var output = new FormData();

		// Analyse or dissect
		if (this.state.action == 'analyse') output.append('testcase_id', $("select[name=testcase_id]").val());
		else output.append('protocol_selection', $("input[name=protocol_selection]").val());

		// The token or the file
		if (!this.state.token && this.state.pcapFile) output.append('pcap_file', this.state.pcapFile[0]);
		else if (this.state.token && !this.state.pcapFile) output.append('token', this.state.token);
		else console.log('ERROR: No token nor pcap file provided, the post request requires one or the other');

		// Send the post request in ajax
		$.ajax({
			url: url,
			type: 'POST',
			cache: false,
			dataType: 'json',
			processData: false,
			contentType: false,
			data: output,
			success: function(input) {
				checkError('POST request on ' + url, input);
				this.tokenManager(input);
			}.bind(this),
			error: function(xhr, status, err) {
				console.error(url, status, err.toString());
			}.bind(this)
		});
	},


	/**
	 * Handler for when the user change the action (dissect or analyse)
	 */
	switchAction: function(optionChoosed) {

		// Check the new value before updating it
		if ($.inArray(optionChoosed.currentTarget.value, acceptedActions) > -1)
			this.setState({action: optionChoosed.currentTarget.value});
		else console.log('WARNING: Unaccepted action value of ' + optionChoosed.currentTarget.value);
	},


	/**
	 * Handler for when the user change the pcap file
	 * This function allows us to always have the value of the file input
	 */
	updatePcapFile: function(newPcapFile) {
		this.setState({pcapFile: newPcapFile.currentTarget.files});
	},


	/**
	 * Function thrown after the element is fully loaded
	 */
	componentDidMount: function() {

		// Get the list of test cases from the server
		$.ajax({
			url: this.props.baseUrl + getTestCasesUrl,
			dataType: 'json',
			success: function(data) {
				checkError('the fetching the test cases', data);
				this.setState({testCases: data});
			}.bind(this),
			error: function(xhr, status, err) {
				console.error(this.props.url, status, err.toString());
			}.bind(this)
		});

		// Get the list of protocols from the server
		$.ajax({
			url: this.props.baseUrl + getProtocolsUrl,
			dataType: 'json',
			success: function(data) {
				checkError('the fetching the protocols', data);
				this.setState({protocols: data});
			}.bind(this),
			error: function(xhr, status, err) {
				console.error(this.props.url, status, err.toString());
			}.bind(this)
		});
	},


	/**
	 * Getter of the initial state for parameters
	 */
	getInitialState: function() {
		return {
			action: 'analyse',
			token: false,
			pcapFile: false,
			testCases: false,
			protocols: false
		};
	},


	/**
	 * Render function for FormBloc
	 */
	render: function() {

		return (
			<form action={ this.props.baseUrl + ((this.state.action == 'analyse') ? analyseUrl : dissectUrl) } method="post" enctype="multipart/form-data" onSubmit={this.handlePcapSubmit} >

				<div className="row">
					<div className="col-sm-6">
						<div className="page-header">
							<h1>Pcap field to {this.state.action}</h1>
						</div>
						{
							(this.state.token)
							?
							<InputGroupBloc inputName="token" inputType="text" addonText="Token" required={true} textOnLeft={true} readOnly={true} inputPlaceholder={this.state.token} onChange={function(){}} />
							:
							<InputGroupBloc inputName="pcap_file" inputType="file" addonText="Enter your pcap file" required={true} textOnLeft={true} readOnly={false} inputPlaceholder="" onChange={this.updatePcapFile} />
						}
					</div>

					<div className="col-sm-6">
						<div className="page-header">
							<h1>{ (this.state.action == 'analyse') ? 'Analysis options' : 'Dissection options' }</h1>
						</div>

						<SelectGroupBloc currentAction={this.state.action} optionGroups={ (this.state.action == 'analyse') ? this.state.testCases : this.state.protocols } />

						<div style={{textAlign: 'center'}}>
							<div className="btn-group" data-toggle="buttons" >
								<RadioButton inputName="options" inputValue="analyse" inputText="Analyse" currentAction={this.state.action} switchAction={this.switchAction} />
								<RadioButton inputName="options" inputValue="dissect" inputText="Dissect" currentAction={this.state.action} switchAction={this.switchAction} />
							</div>
						</div>
					</div>
				</div>

				<div className="row">
					<p style={{textAlign: 'center'}}>
						<input type="submit" value="Execute" className="btn btn-success centered-block" />
					</p>
				</div>
			</form>
		);
	}
});


// The PcapUtility renderer
var PcapUtility = React.createClass({

	/**
	 * Render function for PcapForm
	 */
	render: function() {
		return (
			<div className="row">
				<FormBloc baseUrl={baseUrl} />

				<div className="modal fade" role="dialog" id="error-modal">
					<div className="modal-dialog">
						<div className="modal-content">
							<div className="modal-body">
								<div className="alert alert-danger">
									<button type="button" className="close" data-dismiss="modal" aria-label="Close">
										<span aria-hidden="true">&times;</span>
									</button>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		);
	}
});



// The final ReactDom renderer
ReactDOM.render(
	<PcapUtility />,
	document.getElementById('content')
);