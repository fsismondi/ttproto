// ############### Some parameters ###############

// Some constant values
var baseUrl = 'http://127.0.0.1';
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
				this.props.frameUpdated(input);
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



// The FrameBloc renderer
var FrameBloc = React.createClass({

	/**
	 * Mapped function to parse the protocol stack
	 */
	mapProtocolStack: function(prot) {

		// Check the type value
		if (prot._type == 'protocol') {

			// Increment the protocol stack id
			this.state.protocolStackId++;

			// For all the fields of the protocol
			var frameContent = '';
			var uniqueKey = 0;
			for (var field in prot) {

				// Check that it's not the name of the protocol
				if (field != 'Protocol' && field != '_type') {

					// If the value is an array (like options for CoAP)
					if (Array.isArray(prot[field])) {
						frameContent += '<div key="' + uniqueKey + '">' + field + ': <div class="indent">';
						for (var option in prot[field]) {
							var options = [];
							for (var f in prot[field][option]) {
								frameContent += '<div>' + f + ': ' + prot[field][option][f] + '</div>';
							}
						}
						frameContent += '</div></div>';
					}

					// Just a couple field => value
					else frameContent += '<div key="' + uniqueKey + '">' + field + ': ' + prot[field] + '</div>';

					// Increment the unique key
					uniqueKey++;
				}
			}

			return (
				<div className="panel panel-default">
					<a className="collapsed" role="button" data-toggle="collapse" href={ '#collapse' + this.state.protocolStackId } aria-expanded="false" aria-controls={ 'collapse' + this.state.protocolStackId }>
						<span className="panel-heading" role="tab" id={ 'frame' + this.state.protocolStackId }>
							{prot.Protocol}
						</span>
					</a>

					<div id={ 'collapse' + this.state.protocolStackId } className="panel-collapse collapse" role="tabpanel" aria-labelledby={ 'frame' + this.state.protocolStackId }>
						<div className="panel-body" dangerouslySetInnerHTML={{__html: frameContent}} />
					</div>
				</div>
			);
		}

		console.log('WARNING: MapProtocolStack() received a wrong protocol data');
		return null;
	},


	/**
	 * Getter of the initial state for parameters
	 */
	getInitialState: function() {
		return {
			protocolStackId: false
		};
	},


	/**
	 * Render function for FrameBloc
	 */
	render: function() {

		// Put back to 0 the protocol stack id
		this.state.protocolStackId = 0;

		// Only if this is a correct frame
		if (this.props.frame)
			return (
				<div className="row">
					<div className="col-md-2"></div>

					<div className="col-md-8">
						<div className="panel panel-default">
							<div className="panel-heading">
								<h1 className="panel-title">Frame n°{this.props.frame.id}</h1>
							</div>

							<div className="panel-body">
								<div className="panel-group packet-content" id="frames" role="tablist" aria-multiselectable="true">

									{ this.props.frame.protocol_stack.map(this.mapProtocolStack) }

								</div>
							</div>
						</div>
					</div>

					<div className="col-md-2"></div>
				</div>
				
			);
		else return null;
	}
});



// The FrameNavigationBloc renderer
var FrameNavigationBloc = React.createClass({
	
	/**
	 * Render function for FrameNavigationBloc
	 */
	render: function() {
		return (
			<div className="row">

				<div className="col-xs-3" style={{textAlign: 'center'}}>
					<a href="#"><span className="glyphicon glyphicon-chevron-left arrow" ></span></a>
				</div>

				<div className="col-md-1 visible-lg visible-md"></div>

				<div className="col-xs-6 col-md-4">
					<div className="input-group" style={{marginTop: '10px'}}>
						<span className="input-group-addon" >Directly access to frame </span>
						<input className="form-control" type="text" name="frame-number" placeholder="number" />
						<a className="input-group-addon btn btn-info" type="submit" placeholder="number" >
							<span className="glyphicon glyphicon-fast-forward"></span>
						</a>
					</div>
				</div>

				<div className="col-md-1 visible-lg visible-md"></div>

				<div className="col-xs-3" style={{textAlign: 'center'}}>
					<a href="#"><span className="glyphicon glyphicon-chevron-right arrow" ></span></a>
				</div>

			</div>
		);
	}
});



// The ResultBloc renderer
var ResultBloc = React.createClass({

	/**
	 * Render function for ResultBloc
	 */
	render: function() {
		return (
			<div>
				<div className="page-header" id="result-header">
					<h1>Result</h1>
				</div>

				<FrameBloc frame={this.props.frame} />

				<FrameNavigationBloc />
			</div>
		);
	}
});



// The ErrorModalBloc renderer
var ErrorModalBloc = React.createClass({

	/**
	 * Render function for ErrorModalBloc
	 */
	render: function() {
		return (
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
		);
	}
});



// The PcapUtility renderer
var PcapUtility = React.createClass({

	/**
	 * Function to call when a new frame is to display
	 */
	newFrame: function(data) {

		// Check that the datas are correct and that we have at least one frame
		if (data && data.ok && data._type == 'response') {

			// Check that we have at least one frame
			var frameFoundInResponse = false;
			var id = 0;
			while (!frameFoundInResponse && (id  < data.content.length)) {
				if (data.content[id]._type == 'frame') frameFoundInResponse = true;
				id++;
			}

			// If one found, tell the other elements which one it is
			if (frameFoundInResponse) {

				// Update the state
				this.setState({
					results: data,
					frameId: (id - 1)
				});
			}
		}
	},


	/**
	 * Getter of the initial state for parameters
	 */
	getInitialState: function() {
		return {
			results: false,
			frameId: false
		};
	},


	/**
	 * Render function for PcapForm
	 */
	render: function() {
		return (
			<div>
				<div className="row">
					<FormBloc baseUrl={baseUrl} frameUpdated={this.newFrame} />
				</div>

				{ (this.state.results) ?
					<div className="row">
						<ResultBloc frame={this.state.results.content[this.state.frameId]} />
					</div>
				: null }

				<div className="row">
					<ErrorModalBloc />
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