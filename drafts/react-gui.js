// ############### Some parameters ###############

var baseUrl = 'http://127.0.0.1:2080';
var analyseUrl = '/api/v1/testcase_analyse';
var dissectUrl = '/api/v1/frames_dissect';
var getTestCasesUrl = '/api/v1/get_testcases';
var getProtocolsUrl = '/api/v1/get_protocols';
var acceptedActions = ['analyse', 'dissect'];



// ############### Utility functions ###############
function checkError(errorTrigger, data) {

	// Check the datas received
	if (data && !data.ok && data.type == 'error') {

		// Clear the error message displayer
		$('#error-modal .modal-body .alert').html(
			'<button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>'
		);

		// The error message to display
		var errorMessage = 'An error occured';

		// Check if we have the error trigger
		if (errorTrigger != '') errorMessage += ' during ' + errorTrigger;

		// Check the data we have
		if (data.value != '') errorMessage += '<br/><br/>More informations:</br>' + data.value;
		
		// Display the error itself in a bootstrap model
		$('#error-modal .modal-body .alert').append(errorMessage);
		$('#error-modal').modal('show');
	}
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
				<input id={this.props.inputName} type={this.props.inputType} className="form-control" name={this.props.inputName} placeholder={this.props.inputPlaceholder} required={this.props.required} onChange={this.props.onChange} />
				{ (this.props.textOnLeft) ? null : addonPart }
			</div>
		);
	}
});



// A renderer for the select group
var SelectGroupBloc = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// Analyse action
		if (this.props.currentAction == 'analyse') {
			var optionInputName = 'testcase_id';
			var optionAddonText = 'Test case';
			var expectedType = 'testcase_list';

		// Dissect action
		} else {
			var optionInputName = 'protocol_selection';
			var optionAddonText = 'Protocol';
			var expectedType = 'protocol_list';
		}

		// Check the result
		if (this.props.optionGroups && this.props.optionGroups.ok && this.props.optionGroups.type == expectedType) {
			return (
				<div className="input-group">
					<span className="input-group-addon" >{optionAddonText}</span>
					<select name={optionInputName} className="form-control">
						{
							this.props.optionGroups.value.map(function(o) {
								return (
									<option key={o.name} value={o.name} title={o.description} >{o.name}</option>
								);
							})
						}
					</select>
				</div>
			);

		// An error occured
		} else {
			console.log('WARNING: Couldn\'t retrieve ' + expectedType);
			if (this.props.optionGroups && !this.props.optionGroups.ok && this.props.optionGroups.type == 'error')
				console.log('More informations: ' + this.props.optionGroups.value);
			return null;
		}
	}
});



// The FormBloc renderer
var FormBloc = React.createClass({

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
		output.append('pcap_file', this.state.pcapFile[0]);

		// Analyse or dissect
		if (this.state.action == 'analyse') output.append('testcase_id', $("input[name=testcase_id]").val());
		else output.append('protocol_selection', $("input[name=protocol_selection]").val());

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
			pcapFile: {},
			testCases: {ok: false},
			protocols: {ok: false}
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
						<InputGroupBloc inputName="pcap_file" inputType="file" addonText="Enter your pcap file" required={true} textOnLeft={true} inputPlaceholder="" onChange={this.updatePcapFile} />
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